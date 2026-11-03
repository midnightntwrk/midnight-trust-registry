<script setup lang="ts">
import { onMounted, ref } from "vue";

const props = defineProps<{ encoded: string }>();
const host = ref<HTMLElement | null>(null);

onMounted(async () => {
  if (!host.value) return;
  const mermaid = (await import("mermaid")).default;
  mermaid.initialize({ startOnLoad: false, securityLevel: "strict", theme: "neutral" });
  const id = `tr-diagram-${Math.random().toString(36).slice(2)}`;
  const { svg } = await mermaid.render(id, decodeURIComponent(props.encoded));
  host.value.innerHTML = svg;
});
</script>

<template>
  <div class="tr-diagram" role="img" aria-label="Sequence or architecture diagram">
    <div ref="host" />
  </div>
</template>
