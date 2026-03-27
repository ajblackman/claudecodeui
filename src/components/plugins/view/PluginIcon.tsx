import { useState, useEffect } from 'react';
import DOMPurify from 'dompurify';
import { authenticatedFetch } from '../../../utils/api';

type Props = {
  pluginName: string;
  iconFile: string;
  className?: string;
};

// Module-level cache so repeated renders don't re-fetch
const svgCache = new Map<string, string>();

export default function PluginIcon({ pluginName, iconFile, className }: Props) {
  const url = iconFile
    ? `/api/plugins/${encodeURIComponent(pluginName)}/assets/${encodeURIComponent(iconFile)}`
    : '';
  const [svg, setSvg] = useState<string | null>(url ? (svgCache.get(url) ?? null) : null);

  useEffect(() => {
    if (!url || svgCache.has(url)) return;
    authenticatedFetch(url)
      .then((r) => {
        if (!r.ok) return;
        return r.text();
      })
      .then((text) => {
        if (text && text.trimStart().startsWith('<svg')) {
          // Security: Sanitize SVG to prevent XSS via event handlers/scripts (H7 fix)
          const sanitized = DOMPurify.sanitize(text, {
            USE_PROFILES: { svg: true, svgFilters: true },
            ADD_TAGS: ['svg', 'path', 'g', 'circle', 'rect', 'line', 'polyline', 'polygon', 'ellipse', 'defs', 'clipPath', 'use', 'text', 'tspan'],
            ADD_ATTR: ['viewBox', 'xmlns', 'fill', 'stroke', 'stroke-width', 'stroke-linecap', 'stroke-linejoin', 'd', 'cx', 'cy', 'r', 'rx', 'ry', 'x', 'y', 'width', 'height', 'transform', 'opacity', 'class', 'id', 'clip-path', 'fill-rule', 'clip-rule'],
            FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed', 'form', 'input'],
            FORBID_ATTR: ['onload', 'onerror', 'onclick', 'onmouseover', 'onfocus', 'onblur', 'xlink:href'],
          });
          svgCache.set(url, sanitized);
          setSvg(sanitized);
        }
      })
      .catch(() => {});
  }, [url]);

  if (!svg) return <span className={className} />;

  return (
    <span
      className={className}
      dangerouslySetInnerHTML={{ __html: svg }}
    />
  );
}
