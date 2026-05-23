import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Link, NavLink, useParams } from 'react-router-dom';
import ReactMarkdown, { type Components } from 'react-markdown';
import rehypeHighlight from 'rehype-highlight';
import rehypeSlug from 'rehype-slug';
import remarkGfm from 'remark-gfm';
import SwaggerUI from 'swagger-ui-react';
import 'swagger-ui-react/swagger-ui.css';
// highlight.js styles live in index.css now (themed via CSS vars).
import { docsApi, type DocSummary } from '../api/docs';
import { getToken } from '../api/client';
import { usePageTitle } from '../components/Layout';
import { useToast } from '../components/Toast';

// ── Page shell ───────────────────────────────────────────────────────────────

export function Docs() {
  usePageTitle('Docs');
  const params = useParams<{ slug?: string }>();
  const [toc, setToc] = useState<DocSummary[] | null>(null);
  const [tocError, setTocError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    docsApi
      .list()
      .then((d) => { if (!cancelled) setToc(d); })
      .catch((e) => { if (!cancelled) setTocError(e instanceof Error ? e.message : String(e)); });
    return () => { cancelled = true; };
  }, []);

  // Default the index route ("/docs" with no slug) to the first markdown doc.
  const currentSlug = params.slug ?? toc?.[0]?.slug ?? 'readme';

  return (
    <div className="flex gap-6">
      <nav className="w-[200px] flex-shrink-0">
        <div className="text-[11px] font-semibold uppercase tracking-wider text-muted mb-2">
          API
        </div>
        <DocsNavLink to="/docs/openapi" label="OpenAPI (Swagger)" />

        <div className="text-[11px] font-semibold uppercase tracking-wider text-muted mt-5 mb-2">
          Guides
        </div>
        {tocError && <div className="text-xs text-danger">{tocError}</div>}
        {toc?.map((d) => (
          <DocsNavLink key={d.slug} to={`/docs/${d.slug}`} label={d.title} />
        ))}
      </nav>

      <article className="flex-1 min-w-0">
        {currentSlug === 'openapi'
          ? <SwaggerPanel />
          : <MarkdownPanel slug={currentSlug} />}
      </article>
    </div>
  );
}

function DocsNavLink({ to, label }: { to: string; label: string }) {
  return (
    <NavLink
      to={to}
      end
      className={({ isActive }) =>
        `block px-2 py-1.5 rounded text-sm ${
          isActive ? 'bg-surface2 text-text font-semibold' : 'text-muted hover:text-text'
        }`
      }
    >
      {label}
    </NavLink>
  );
}

// ── Markdown panel ───────────────────────────────────────────────────────────

/**
 * Rewrite a relative href written for the GitHub-rendered docs into something
 * sensible in-app:
 *
 *   `installation.md`             → `/docs/installation`        (SPA nav)
 *   `architecture.md#url-symmetry`→ `/docs/architecture#url-...` (SPA nav)
 *   `#section`                    → unchanged                   (in-page anchor)
 *   `https://...`, `mailto:...`   → unchanged                   (external)
 */
/**
 * Highlight a heading that was just jumped to, hold the highlight long
 * enough for the eye to find it, then fade smoothly to transparent.
 *
 * Timing (total ≈ 5.5s):
 *   0.0s  snap to full highlight (no transition)
 *   3.0s  begin fade
 *   5.5s  fully transparent, inline styles cleaned up
 *
 * Imperative inline styles + CSS transitions rather than the Web Animations
 * API: makes each phase visible in DevTools, avoids any browser optimization
 * that might collapse an identical-keyframe hold, and is trivial to retune.
 */
const FLASH_HOLD_MS = 3000;
const FLASH_FADE_MS = 2500;
const FLASH_BG    = 'rgba(99, 102, 241, 0.40)';
const FLASH_RING  = '0 0 0 6px rgba(99, 102, 241, 0.18)';

type FlashTarget = HTMLElement & {
  __flashHoldTimer?: number;
  __flashDoneTimer?: number;
};

function flashHeading(el: Element | null): void {
  if (!el) return;
  const target = el as FlashTarget;

  // Cancel any in-flight flash on the same element so a re-click restarts
  // the sequence cleanly instead of stacking timers.
  if (target.__flashHoldTimer !== undefined) window.clearTimeout(target.__flashHoldTimer);
  if (target.__flashDoneTimer !== undefined) window.clearTimeout(target.__flashDoneTimer);

  // Frame 0: snap to highlight. Disable transitions so the colour appears
  // instantly with no easing.
  target.style.transition = 'none';
  target.style.backgroundColor = FLASH_BG;
  target.style.boxShadow = FLASH_RING;
  // Flush a layout/paint so the highlight commits before we (re-)enable the
  // transition. Reading offsetWidth is the cheapest way to force this.
  void target.offsetWidth;

  // After the hold, kick the transition to transparent.
  target.__flashHoldTimer = window.setTimeout(() => {
    target.style.transition = `background-color ${FLASH_FADE_MS}ms ease-out, box-shadow ${FLASH_FADE_MS}ms ease-out`;
    target.style.backgroundColor = 'rgba(99, 102, 241, 0)';
    target.style.boxShadow = '0 0 0 6px rgba(99, 102, 241, 0)';
  }, FLASH_HOLD_MS);

  // Once the fade completes, drop the inline styles entirely so the heading
  // is back under stylesheet control.
  target.__flashDoneTimer = window.setTimeout(() => {
    target.style.transition = '';
    target.style.backgroundColor = '';
    target.style.boxShadow = '';
    target.__flashHoldTimer = undefined;
    target.__flashDoneTimer = undefined;
  }, FLASH_HOLD_MS + FLASH_FADE_MS + 200);
}

function rewriteDocHref(href: string): { target: string; internal: boolean } {
  if (!href) return { target: href, internal: false };
  if (/^[a-z]+:/i.test(href) || href.startsWith('//')) return { target: href, internal: false };
  if (href.startsWith('#') || href.startsWith('/')) return { target: href, internal: href.startsWith('/docs') };

  const hashIdx = href.indexOf('#');
  const path = hashIdx >= 0 ? href.slice(0, hashIdx) : href;
  const hash = hashIdx >= 0 ? href.slice(hashIdx) : '';

  // Only intercept things that look like sibling .md files. Anything else
  // (e.g. a fragment like `foo.txt`, an image path) is left alone.
  const mdMatch = path.match(/^([^/]+?)\.md$/i);
  if (!mdMatch) return { target: href, internal: false };

  return { target: `/docs/${mdMatch[1].toLowerCase()}${hash}`, internal: true };
}

function MarkdownPanel({ slug }: { slug: string }) {
  const [body, setBody] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const toast = useToast();

  useEffect(() => {
    let cancelled = false;
    setBody(null);
    setError(null);
    docsApi
      .raw(slug)
      .then((md) => { if (!cancelled) setBody(md); })
      .catch((e) => { if (!cancelled) setError(e instanceof Error ? e.message : String(e)); });
    return () => { cancelled = true; };
  }, [slug]);

  // Once the new body has rendered, jump to any anchor in the URL. react-router
  // doesn't scroll for hash changes on its own.
  useEffect(() => {
    if (body === null) return;
    const hash = window.location.hash.replace(/^#/, '');
    if (!hash) return;
    // Allow the next paint so the heading element exists.
    queueMicrotask(() => {
      const el = document.getElementById(hash);
      el?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      flashHeading(el);
    });
  }, [body, slug]);

  // Memoise the renderer overrides so react-markdown sees a stable identity
  // across re-renders. Without this, every render hands react-markdown a new
  // `components` object literal, which re-mounts heading DOM nodes — and
  // remounted nodes lose the inline-style flash that was animating on them.
  const components = useMemo<Components>(
    () => ({
      a({ href, children, node: _node, ...rest }) {
        const { target, internal } = rewriteDocHref(href ?? '');
        if (internal) {
          return <Link to={target}>{children}</Link>;
        }
        const isExternal = /^https?:/i.test(target);
        return (
          <a
            href={target}
            {...(isExternal ? { target: '_blank', rel: 'noreferrer noopener' } : {})}
            {...rest}
          >
            {children}
          </a>
        );
      },
      h2: ({ id, children }) =>
        <HeadingWithAnchor level={2} id={id} toast={toast}>{children}</HeadingWithAnchor>,
      h3: ({ id, children }) =>
        <HeadingWithAnchor level={3} id={id} toast={toast}>{children}</HeadingWithAnchor>,
      h4: ({ id, children }) =>
        <HeadingWithAnchor level={4} id={id} toast={toast}>{children}</HeadingWithAnchor>,
    }),
    [toast],
  );

  if (error) return <div className="alert alert-error">{error}</div>;
  if (body === null) return <div className="flex items-center gap-2 text-muted"><span className="spinner" /> Loading...</div>;

  return (
    <div className="prose-docs">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        rehypePlugins={[rehypeSlug, rehypeHighlight]}
        components={components}
      >
        {body}
      </ReactMarkdown>
    </div>
  );
}

/**
 * A heading that exposes its rehype-slug `id` as a permalink. On click of the
 * link icon: copy the absolute URL to the clipboard, update the address bar
 * (so the back button works), and scroll the heading into view.
 *
 * The icon is hidden until hover (CSS via `.heading-anchor`) to keep the doc
 * flow clean. Skipping `h1` on purpose — the doc title shouldn't get an
 * inline anchor.
 */
function HeadingWithAnchor({
  level,
  id,
  children,
  toast,
}: {
  level: 2 | 3 | 4;
  id: string | undefined;
  children: ReactNode;
  toast: ReturnType<typeof useToast>;
}) {
  const Tag = (`h${level}`) as 'h2' | 'h3' | 'h4';
  const slug = id ?? '';

  const onCopy = async () => {
    if (!slug) return;
    const url = `${window.location.origin}${window.location.pathname}#${slug}`;
    // Update the address bar without a full navigation so the heading scroll
    // happens immediately and the user can paste-share what they see.
    window.history.replaceState(null, '', `#${slug}`);
    const el = document.getElementById(slug);
    el?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    flashHeading(el);
    try {
      await navigator.clipboard.writeText(url);
      toast.success('Link copied to clipboard');
    } catch {
      toast.info(`Link: ${url}`);
    }
  };

  return (
    <Tag id={slug} className="heading-anchor group">
      {children}
      {slug && (
        <button
          type="button"
          className="heading-anchor-btn"
          aria-label="Copy link to this section"
          title="Copy link"
          onClick={onCopy}
        >
          {/* link / chain icon */}
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
               strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
            <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
            <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
          </svg>
        </button>
      )}
    </Tag>
  );
}

// ── Swagger panel ────────────────────────────────────────────────────────────

/**
 * Render Swagger UI against the live /api/openapi.json. "Try it out" is
 * enabled and uses the in-app session: the `session=` cookie is attached
 * automatically (same-origin requests) and, if there's a bearer token in
 * sessionStorage, we inject it via `requestInterceptor` so Swagger UI's
 * sample requests authenticate as the logged-in user without the operator
 * having to re-paste credentials.
 *
 * Trade-off the user opted into: clicking "Try it out" on a destructive
 * endpoint (DELETE /api/certificates/{id}, …) really does hit production
 * data. The Authorize dialog isn't required, by design.
 */
function SwaggerPanel() {
  // The @types declaration types `req` as the DOM `Request` class, but at
  // runtime swagger-ui-react hands us a plain mutable shape with bare
  // `headers` and `credentials` properties. There's no way to satisfy
  // the DOM signature without `any`, so spell it out here.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const requestInterceptor = useMemo<any>(
    () => (req: { headers: Record<string, string>; credentials?: string }) => {
      req.credentials = 'same-origin';
      const tok = getToken();
      if (tok && !req.headers['Authorization']) {
        req.headers['Authorization'] = `Bearer ${tok}`;
      }
      return req;
    },
    [],
  );

  return (
    <div className="swagger-host">
      <SwaggerUI
        url="/api/openapi"
        requestInterceptor={requestInterceptor}
        docExpansion="list"
        defaultModelsExpandDepth={0}
        persistAuthorization
      />
    </div>
  );
}
