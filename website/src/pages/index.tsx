import Layout from '@theme/Layout'
import Link from '@docusaurus/Link'
import useDocusaurusContext from '@docusaurus/useDocusaurusContext'
import styles from './index.module.css'

/**
 * The landing page.
 *
 * Deliberately short, and deliberately leads with the status. This is pre-1.0
 * software for authenticating people, and a landing page that opens with
 * features rather than with "do not deploy this yet" is one that gets somebody
 * into trouble.
 */
export default function Home() {
  const { siteConfig } = useDocusaurusContext()

  return (
    <Layout description={siteConfig.tagline}>
      <main className={styles.main}>
        <h1 className={styles.title}>Cardinal</h1>
        <p className={styles.tagline}>{siteConfig.tagline}.</p>

        <div className={styles.warning}>
          <strong>Pre-1.0, and not production ready.</strong> No stable API, no
          upgrade path between versions, and no security audit. If you need a
          working identity platform today, deploy{' '}
          <a href="https://github.com/kanidm/kanidm">Kanidm</a> instead.
        </div>

        <div className={styles.actions}>
          <Link className="button button--primary button--lg" to="/docs/first-run">
            Ten-minute walkthrough
          </Link>
          <Link className="button button--secondary button--lg" to="/docs/architecture">
            How it is built
          </Link>
        </div>

        <dl className={styles.claims}>
          <dt>Identity is an immutable UUIDv7</dt>
          <dd>
            Names, emails and group placement are attributes hanging off it, so
            renaming somebody is an <code>UPDATE</code> rather than a migration.
          </dd>

          <dt>Access grants carry a validity period</dt>
          <dd>
            Time-boxed access is an <code>INSERT</code> with a bounded range and
            expiry is enforced by the query, not by a job that might not run.
            &ldquo;Who had access in March&rdquo; is a <code>WHERE</code> clause.
          </dd>

          <dt>One policy engine decides everything</dt>
          <dd>
            Web access, sign-in to each application, SSH certificates, sudo and
            Cardinal&rsquo;s own admin API. Every decision records the rule that
            made it, so &ldquo;why was I denied&rdquo; has an answer.
          </dd>

          <dt>Passkeys only</dt>
          <dd>There is no password column.</dd>
        </dl>
      </main>
    </Layout>
  )
}
