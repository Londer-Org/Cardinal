import type { Config } from '@docusaurus/types'
import type * as Preset from '@docusaurus/preset-classic'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

/**
 * The documentation site.
 *
 * Two things are deliberate.
 *
 * The docs themselves live in ../docs and are not copied here. They are read by
 * people working in the repository as often as by people on the website, and a
 * second copy under website/ would be the one that goes stale — the plan's own
 * measure of documentation is "have somebody who isn't you deploy it from the
 * README alone", which they will do from a checkout.
 *
 * The version comes from the VERSION file rather than being written here. It is
 * the same number the binaries report and the same one the release tag carries,
 * and a site announcing a different one would be a fourth place to keep in step.
 */
const version = readFileSync(resolve(__dirname, '../VERSION'), 'utf8').trim()

const config: Config = {
  title: 'Cardinal',
  tagline:
    'A directory and identity platform where identity is immutable, access is ' +
    'time-bounded by default, and every authorization decision can explain itself',
  favicon: 'img/favicon.ico',

  url: 'https://londer-org.github.io',
  baseUrl: '/Cardinal/',
  organizationName: 'Londer-Org',
  projectName: 'Cardinal',
  trailingSlash: false,

  // A broken link is a docs bug, and a warning is a docs bug nobody fixes.
  // This caught two on its first run: docs/threat-model.md and
  // docs/integration.md both pointed at a ROADMAP.md that had never existed,
  // from the "known gaps" section a reader is most likely to follow.
  onBrokenLinks: 'throw',

  future: { v4: true },

  markdown: {
    hooks: { onBrokenMarkdownLinks: 'throw' },
    // CommonMark, not MDX.
    //
    // These files live in ../docs and are read in a checkout and on GitHub as
    // often as here, so they are markdown in the ordinary sense: `<name>` in a
    // usage line, `<!-- -->` in a comment. MDX treats `<` as the start of JSX
    // and fails on all of it.
    //
    // `detect` keeps .mdx available if a page ever genuinely wants a component,
    // without making every existing document pay for the possibility.
    format: 'detect',
  },

  presets: [
    [
      'classic',
      {
        docs: {
          path: '../docs',
          routeBasePath: 'docs',
          sidebarPath: './sidebars.ts',
          editUrl: 'https://github.com/Londer-Org/Cardinal/tree/main/',

          // Versioning.
          //
          // `npm run docs:version 0.2.0` snapshots the current docs into
          // versioned_docs/, and the picker in the navbar switches between
          // them. The working tree stays "Next", which is what somebody
          // reading from a checkout of main is actually running.
          lastVersion: 'current',
          versions: {
            current: {
              label: version,
              path: '',
            },
          },
        },
        blog: false,
        theme: { customCss: './src/css/custom.css' },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    navbar: {
      title: 'Cardinal',
      items: [
        { type: 'docSidebar', sidebarId: 'docs', position: 'left', label: 'Docs' },
        // The picker. Present from the first release rather than added at the
        // second, so the URL shape never has to change.
        { type: 'docsVersionDropdown', position: 'right' },
        {
          href: 'https://github.com/Londer-Org/Cardinal',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            { label: 'First run', to: '/docs/first-run' },
            { label: 'Architecture', to: '/docs/architecture' },
            { label: 'Threat model', to: '/docs/threat-model' },
          ],
        },
        {
          title: 'Project',
          items: [
            { label: 'GitHub', href: 'https://github.com/Londer-Org/Cardinal' },
            {
              label: 'Security policy',
              href: 'https://github.com/Londer-Org/Cardinal/blob/main/SECURITY.md',
            },
          ],
        },
      ],
      copyright: `Cardinal ${version} · Apache-2.0 · pre-1.0, not production ready`,
    },
    prism: {
      additionalLanguages: ['bash', 'go', 'sql', 'toml', 'json'],
    },
  } satisfies Preset.ThemeConfig,
}

export default config
