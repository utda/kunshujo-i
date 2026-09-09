/**
 * `npm audit` の結果を判定する。high 以上があれば失敗する。
 *
 * `npm audit --audit-level=high` をそのまま使わないのは、直せない既知の件で
 * CI が止まり続け、そのうち誰も見なくなるため。除外する場合は下の ALLOW に
 * 理由と期限を書いて残す。期限を過ぎたら、除外していても失敗させる。
 * 「なぜ放置しているのか」と「いつ見直すのか」が、常にこのファイルに残る。
 *
 * このリポジトリは Nuxt 2 のままで、報告が 200 件を超える。1 件ずつ ALLOW に
 * 書くのは現実的でないので、下の BASELINE に「今この時点で出ているもの」を
 * 丸ごと記録し、**それ以外が新しく出たときだけ落とす**形にした。
 * 「気づかないまま新しい脆弱性が増える」ことは防げる。
 *
 * 使い方: node scripts/audit.mjs
 */
import { execFileSync } from 'node:child_process'

/**
 * 個別の除外。BASELINE より優先度が高い扱いではなく、単に「後から個別の判断で
 * 外したもの」を置く場所。
 * @type {{ id: string, package: string, until: string, reason: string }[]}
 */
const ALLOW = []

/**
 * 2026-09-08 時点で出ていた high 以上の advisory を、まとめて記録したもの。
 *
 * なぜまとめて外すのか:
 *
 * - このサイトは Nuxt 2 (2.15.x) で、Nuxt 2 は 2023-12-31 に EOL になっている。
 *   webpack 4 / babel 7 / postcss 7 という古いビルドチェーンを Nuxt 2 自身が
 *   固定しているため、webpack・terser・loader-utils・elliptic・tar などは
 *   「上流に修正版があっても Nuxt 2 が引き上げてくれない」状態にある。
 * - `npm audit fix --package-lock-only` は ERESOLVE (peer 依存の衝突) で失敗し、
 *   1 件も直せないことを実測で確認した (2026-09-08、Docker の node:22 上)。
 * - 公開しているのは `npm run generate` が出す静的 HTML を GitHub Pages に
 *   置いたものだけで、サーバは動いていない。報告の多くを占める
 *   @nuxt/webpack・terser・loader-utils・webpack-dev-middleware・launch-editor
 *   などのビルド時 / 開発サーバ専用のものは、公開物には一切含まれない。
 * - ブラウザに載る側 (axios, vuetify, prismjs, moment など) は残るが、これらは
 *   Nuxt 2 のプラグイン群が固定しており、根本的に解消するには Nuxt 3 への移行が要る。
 *   その移行をやるかどうかの判断自体がまだ済んでいない。
 *
 * したがって until はこの baseline 全体の見直し期限であり、
 * **2026-12-08 までに Nuxt 3 へ移行するかどうかを決める**、という意味になる。
 * 決めないまま日付を越えると、この CI は落ちる。
 */
const BASELINE = {
  until: '2026-12-08',
  ids: [
  'GHSA-fv7c-fp4j-7gwp', // @babel/plugin-transform-modules-systemjs (high)
  'GHSA-67hx-6x53-jw92', // @babel/traverse (critical)
  'GHSA-fwr7-v2mv-hh25', // async (high)
  'GHSA-3g43-6gmg-66jw', // axios (high)
  'GHSA-3p68-rc4w-qgx5', // axios (moderate)
  'GHSA-43fc-jf86-j433', // axios (high)
  'GHSA-5c9x-8gcm-mpgx', // axios (moderate)
  'GHSA-62hf-57xw-28j9', // axios (moderate)
  'GHSA-6chq-wfr3-2hj9', // axios (high)
  'GHSA-7q8q-rj6j-mhjq', // axios (moderate)
  'GHSA-898c-q2cr-xwhg', // axios (moderate)
  'GHSA-fvcv-3m26-pcqx', // axios (moderate)
  'GHSA-hfxv-24rg-xrqf', // axios (high)
  'GHSA-j5f8-grm9-p9fc', // axios (high)
  'GHSA-jr5f-v2jv-69x6', // axios (high)
  'GHSA-m7pr-hjqh-92cm', // axios (moderate)
  'GHSA-mmx7-hfxf-jppx', // axios (moderate)
  'GHSA-p92q-9vqr-4j8v', // axios (high)
  'GHSA-pf86-5x62-jrwf', // axios (high)
  'GHSA-pjwm-pj3p-43mv', // axios (high)
  'GHSA-pmwg-cvhr-8vh7', // axios (high)
  'GHSA-vf2m-468p-8v99', // axios (moderate)
  'GHSA-w9j2-pvgh-6h63', // axios (moderate)
  'GHSA-wf5p-g6vw-rhxx', // axios (moderate)
  'GHSA-xhjh-pmcv-23jw', // axios (low)
  'GHSA-xx6v-rp6x-q39c', // axios (moderate)
  'GHSA-3jxr-9vmj-r5cp', // brace-expansion (high)
  'GHSA-f886-m6hf-6m8v', // brace-expansion (moderate)
  'GHSA-mh99-v99m-4gvg', // brace-expansion (high)
  'GHSA-rgw5-rvv9-x895', // brace-expansion (high)
  'GHSA-v6h2-p8h4-qcjw', // brace-expansion (low)
  'GHSA-grv7-fg5c-xmjg', // braces (high)
  'GHSA-x9w5-v3q2-3rhw', // browserify-sign (high)
  'GHSA-73wf-gq98-2v4g', // browserslist (high)
  'GHSA-c83g-rgw3-j3cx', // browserslist (high)
  'GHSA-cpq7-6gpm-g9rc', // cipher-base (critical)
  'GHSA-3xgq-45jj-v275', // cross-spawn (high)
  'GHSA-vcc3-ghjq-m6fr', // decode-uri-component (moderate)
  'GHSA-w573-4hg7-7wgq', // decode-uri-component (high)
  'GHSA-737v-mqg7-c878', // defu (high)
  'GHSA-33hq-fvwr-56pm', // devalue (low)
  'GHSA-8qm3-746x-r74r', // devalue (low)
  'GHSA-cfw5-2vxh-hr84', // devalue (moderate)
  'GHSA-vj54-72f3-p5jv', // devalue (high)
  'GHSA-434g-2637-qmqr', // elliptic (low)
  'GHSA-49q7-c7j4-3p7m', // elliptic (low)
  'GHSA-848j-6mx2-7j84', // elliptic (low)
  'GHSA-977x-g7h5-7qgw', // elliptic (low)
  'GHSA-f7q4-pwc6-w24p', // elliptic (low)
  'GHSA-fc9h-whq2-v747', // elliptic (low)
  'GHSA-vjh7-7g9h-fjfh', // elliptic (critical)
  'GHSA-25h7-pfq9-p65f', // flatted (high)
  'GHSA-rf6f-7fwh-wjgh', // flatted (high)
  'GHSA-74fj-2j2h-c42q', // follow-redirects (high)
  'GHSA-cxjh-pqwp-8mfp', // follow-redirects (moderate)
  'GHSA-jchw-25xp-jwwc', // follow-redirects (moderate)
  'GHSA-pw2r-vq6v-hr8c', // follow-redirects (moderate)
  'GHSA-r4q5-vmmm-2653', // follow-redirects (moderate)
  'GHSA-pfq8-rq6v-vf5m', // html-minifier (high)
  'GHSA-4www-5p9h-95mh', // http-proxy-middleware (moderate)
  'GHSA-64mm-vxmg-q3vj', // http-proxy-middleware (moderate)
  'GHSA-9gqv-wp59-fq42', // http-proxy-middleware (moderate)
  'GHSA-c7qv-q95q-8v27', // http-proxy-middleware (high)
  'GHSA-2p57-rm9w-gvfp', // ip (high)
  'GHSA-78xj-cgh5-2h22', // ip (low)
  'GHSA-qjx8-664m-686j', // js-cookie (high)
  'GHSA-2883-xcg3-v3hh', // js-yaml (high)
  'GHSA-52cp-r559-cp3m', // js-yaml (high)
  'GHSA-5p4m-2wfm-xmqj', // js-yaml (high)
  'GHSA-h67p-54hq-rp68', // js-yaml (moderate)
  'GHSA-mh29-5h37-fv8m', // js-yaml (moderate)
  'GHSA-9c47-m6qq-7p4h', // json5 (high)
  'GHSA-c27g-q93r-2cwf', // launch-editor (high)
  'GHSA-v6wh-96g9-6wx3', // launch-editor (moderate)
  'GHSA-3rfm-jhwj-7488', // loader-utils (high)
  'GHSA-76p3-8jx3-jpfq', // loader-utils (critical)
  'GHSA-hhq3-ff78-jv3g', // loader-utils (high)
  'GHSA-f23m-r3pf-42rh', // lodash (moderate)
  'GHSA-r5fr-rjxr-66jc', // lodash, lodash.template (high)
  'GHSA-xxjr-mmjv-4gpg', // lodash (moderate)
  'GHSA-35jh-r3h4-6jhm', // lodash.template (high)
  'GHSA-952p-6rrq-rcjv', // micromatch (moderate)
  'GHSA-23c5-xmqv-rm74', // minimatch (high)
  'GHSA-3ppc-4f35-3m26', // minimatch (high)
  'GHSA-7r86-cg39-jmmj', // minimatch (high)
  'GHSA-f8q6-p94x-37v3', // minimatch (high)
  'GHSA-xvch-5gv4-984h', // minimist (critical)
  'GHSA-8hfj-j24r-96c4', // moment (high)
  'GHSA-wc69-rhjr-hc9g', // moment (high)
  'GHSA-28wg-ghj8-5hjv', // nanoid (high)
  'GHSA-2v37-7h3g-55p8', // nanoid (high)
  'GHSA-mwcw-c2x4-8c55', // nanoid (moderate)
  'GHSA-qrpm-p2h7-hrv2', // nanoid (moderate)
  'GHSA-xwg4-73v4-xw9w', // nanoid (high)
  'GHSA-r683-j2x4-v87g', // node-fetch (high)
  'GHSA-rp65-9cf3-cjxr', // nth-check (high)
  'GHSA-m3q2-p4fw-w38m', // nuxt (low)
  'GHSA-vf6r-87q4-2vjf', // nuxt (moderate)
  'GHSA-8g77-54rh-46hx', // parse-git-config (high)
  'GHSA-3j8f-xvm3-ffx4', // parse-path (high)
  'GHSA-4p35-cfcx-8653', // parse-url (high)
  'GHSA-7f3x-x4pr-wqhj', // parse-url (critical)
  'GHSA-j9fq-vwqv-2fm2', // parse-url (critical)
  'GHSA-jpp7-7chh-cf67', // parse-url (moderate)
  'GHSA-pqw5-jmp5-px4v', // parse-url (moderate)
  'GHSA-q6wq-5p59-983w', // parse-url (moderate)
  'GHSA-h7cp-r72f-jxh6', // pbkdf2 (critical)
  'GHSA-v62p-rq8g-8h59', // pbkdf2 (critical)
  'GHSA-3v7f-55p6-f55p', // picomatch (moderate)
  'GHSA-c2c7-rcm5-vvqj', // picomatch (high)
  'GHSA-6g55-p6wh-862q', // postcss (high)
  'GHSA-7fh5-64p2-3v2j', // postcss (moderate)
  'GHSA-fxqj-rqcc-2cmp', // postcss (moderate)
  'GHSA-qx2v-qp2m-jg93', // postcss (moderate)
  'GHSA-r28c-9q8g-f849', // postcss (high)
  'GHSA-3949-f494-cm99', // prismjs (high)
  'GHSA-x7hr-w5r2-h6wg', // prismjs (moderate)
  'GHSA-4mjr-xmp4-gh2g', // qs (moderate)
  'GHSA-6rw7-vpxm-498p', // qs (moderate)
  'GHSA-hrpp-h998-j3pp', // qs (high)
  'GHSA-w7fw-mjwx-w883', // qs (low)
  'GHSA-c2qf-rxjj-qqgw', // semver (high)
  'GHSA-5c6j-r48x-rmvq', // serialize-javascript (high)
  'GHSA-76p7-773f-r4q5', // serialize-javascript (moderate)
  'GHSA-qj8w-gfj5-8c6v', // serialize-javascript (moderate)
  'GHSA-95m3-7q98-8xr5', // sha.js (critical)
  'GHSA-395f-4hp3-45gv', // shell-quote (high)
  'GHSA-w7jw-789q-3m8p', // shell-quote (critical)
  'GHSA-2p49-hgcm-8545', // svgo (high)
  'GHSA-4vpr-x523-8j87', // svgo (moderate)
  'GHSA-w27v-7q3p-w38r', // svgo (high)
  'GHSA-23hp-3jrh-7fpw', // tar (critical)
  'GHSA-34x7-hfp2-rc4v', // tar (high)
  'GHSA-83g3-92jg-28cx', // tar (high)
  'GHSA-8qq5-rm4j-mr97', // tar (high)
  'GHSA-8x88-c5mf-7j5w', // tar (high)
  'GHSA-9ppj-qmqm-q256', // tar (high)
  'GHSA-f5x3-32g6-xq36', // tar (moderate)
  'GHSA-gvwx-54wh-qm9j', // tar (moderate)
  'GHSA-qffp-2rhf-9h96', // tar (high)
  'GHSA-r292-9mhp-454m', // tar (high)
  'GHSA-r6q2-hw4h-h46w', // tar (high)
  'GHSA-vmf3-w455-68vh', // tar (moderate)
  'GHSA-w8wr-v893-vjvp', // tar (moderate)
  'GHSA-4wf5-vphf-c2xc', // terser (high)
  'GHSA-52f5-9888-hmc6', // tmp (low)
  'GHSA-ph9p-34f9-6g65', // tmp (high)
  'GHSA-fhg7-m89q-25r3', // ua-parser-js (high)
  'GHSA-3jp5-5f8r-q2wg', // vuetify (high)
  'GHSA-9w3x-85mw-4fwm', // vuetify (moderate)
  'GHSA-q4q5-c5cv-2p68', // vuetify (moderate)
  'GHSA-38r7-794h-5758', // webpack (low)
  'GHSA-4vvj-4cpr-p986', // webpack (moderate)
  'GHSA-8fgc-7cc6-rx7x', // webpack (low)
  'GHSA-hc6q-2mpp-qw7j', // webpack (critical)
  'GHSA-wr3j-pwj9-hqq6', // webpack-dev-middleware (high)
  'GHSA-3h5v-q93c-6h6q', // ws (high)
  'GHSA-96hv-2xvq-fx4p', // ws (high)
  ],
}

function audit() {
  try {
    return JSON.parse(
      execFileSync('npm', ['audit', '--json'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
    )
  } catch (error) {
    // 脆弱性があると npm audit は終了コード 1 を返す。出力は標準出力に出ている。
    if (error.stdout) return JSON.parse(error.stdout)
    throw error
  }
}

const today = new Date().toISOString().slice(0, 10)
const report = audit()
const baselineActive = BASELINE.until >= today
const serious = []
const seenInBaseline = new Set()

for (const [name, entry] of Object.entries(report.vulnerabilities ?? {})) {
  if (entry.severity !== 'high' && entry.severity !== 'critical') continue
  for (const via of entry.via) {
    if (typeof via !== 'object') continue
    const id = via.url?.split('/').pop() ?? via.source
    const allowed = ALLOW.find((a) => a.id === id)
    if (allowed && allowed.until >= today) continue
    if (BASELINE.ids.includes(id)) {
      seenInBaseline.add(id)
      if (baselineActive) continue
    }
    serious.push({
      name,
      severity: entry.severity,
      title: via.title,
      url: via.url,
      expired: allowed ? allowed.until : BASELINE.ids.includes(id) ? BASELINE.until : null,
    })
  }
}

for (const a of ALLOW) {
  if (a.until < today) {
    console.error(`除外の期限切れ: ${a.package} (${a.id}) の期限 ${a.until} を過ぎています。見直してください。`)
  }
}
if (!baselineActive) {
  console.error(`BASELINE の期限 ${BASELINE.until} を過ぎています。Nuxt 3 への移行の可否を決めてください。`)
}

if (serious.length === 0) {
  console.log(
    `high 以上の新規の脆弱性なし (BASELINE ${seenInBaseline.size}/${BASELINE.ids.length} 件が該当、期限 ${BASELINE.until})`
  )
  // baseline に載っているのに、もう出てこなくなったものは掃除してよい。
  const gone = BASELINE.ids.filter((id) => !seenInBaseline.has(id))
  if (gone.length > 0) {
    console.log(`  もう出なくなった BASELINE の項目が ${gone.length} 件あります。削って構いません:`)
    for (const id of gone) console.log(`    ${id}`)
  }
  process.exit(0)
}

console.error(`BASELINE に無い high 以上の脆弱性が ${serious.length} 件あります:`)
for (const s of serious) {
  const note = s.expired ? ` [除外の期限 ${s.expired} 切れ]` : ''
  console.error(`  ${s.severity.padEnd(8)} ${s.name}: ${s.title}${note}`)
  console.error(`           ${s.url}`)
}
process.exit(1)
