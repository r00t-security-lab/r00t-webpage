module.exports = {
  title: 'r00t信息安全战队',
  description: '分享 | 求知 | 提升',
  dest: 'web',
  markdown: {
        lineNumbers: true
   },
  themeConfig: {
    nav: [
      // { text: '2023新生赛', link: '/rtctf.html' },
      { text: '财务公开', link: '/finance.html' },
      { text: '知识库', link: '/kb/' },
      { text: 'WriteUp', link: '/writeup/' },
      { text: '原 Wiki', link: '/wiki/' }
    ]
  },
  plugins: [
    [
      '@vuepress/google-analytics',
      {
        'ga': 'UA-180711257-1'
      }
    ]
  ]
}
