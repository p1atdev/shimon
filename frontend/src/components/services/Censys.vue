<template>
  <div class="box content is-normal">
    <h4 class="is-size-4">
      <span class="icon">
        <img src="https://www.google.com/s2/favicons?domain=censys.io" alt="shodan" />
      </span>
      Censys
    </h4>
    <QueryTags :queries="queries"></QueryTags>
  </div>
</template>

<script lang="ts">
import * as qs from "qs"
import { computed, defineComponent, type PropType } from "vue"

import QueryTags from "@/components/services/QueryTags.vue"
import type { Fingerprint, Query } from "@/types"

export default defineComponent({
  name: "CensysComponent",
  props: {
    fingerprint: {
      type: Object as PropType<Fingerprint>,
      required: true
    }
  },
  components: { QueryTags },
  setup(props) {
    const createSearchLink = (q: string): string => {
      const baseUrl = "https://search.censys.io/search?"
      const resource = "hosts"
      const params = {
        q,
        resource
      }
      return baseUrl + qs.stringify(params)
    }
    const createCertificatesLink = (sha256: string): string => {
      const baseUrl = "https://search.censys.io/certificates/"
      return baseUrl + sha256
    }

    const queries = computed<Query[]>(() => {
      const q: Query[] = [
        {
          key: "HTML",
          query: `services.http.response.body_hash:"sha1:${props.fingerprint.html.sha1}"`,
          link: createSearchLink(`services.http.response.body_hash:"sha1:${props.fingerprint.html.sha1}"`)
        }
      ]

      if (props.fingerprint.html.title) {
        const query = `services.http.response.html_title:"${props.fingerprint.html.title}"`
        q.push({ key: "Title", query: query, link: createSearchLink(query) })
      }

      if (props.fingerprint.certificate) {
        q.push({
          key: "Certificate Search",
          query: props.fingerprint.certificate.sha256,
          link: createSearchLink(props.fingerprint.certificate.sha256)
        })

        q.push({
          key: "Certificate Details",
          query: props.fingerprint.certificate.sha256,
          link: createCertificatesLink(props.fingerprint.certificate.sha256)
        })
      }

      if (props.fingerprint.tls) {
        const query = `services.jarm.fingerprint:"${props.fingerprint.tls.jarm}"`
        q.push({
          key: "JARM",
          query: query,
          link: createSearchLink(query)
        })
      }

      ;(props.fingerprint.dns.a || []).forEach((record) => {
        const query = `ip:${record.host}`
        q.push({ key: "A", query: query, link: createSearchLink(query) })
      })

      return q
    })

    return { queries }
  }
})
</script>
