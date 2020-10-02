<template>
  <p>共 {{ total }} 元</p>
</template>

<script>
export default {
  name: "financialStatistics",
  data() {
    return {
      total: 0,
    };
  },
  mounted() {
    this.total = Array.from(this.$parent.$el.querySelectorAll("tbody > tr"))
      .map((x) => Number(x.children[2].innerText))
      .reduce((acc, cnt) => cnt + acc);
  },
};
</script>
