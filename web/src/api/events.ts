import { useEffect, useRef } from 'react';

interface CertEventHandlers {
  onChanged?: (id: string) => void;
  onDeleted?: (id: string) => void;
}

/**
 * Subscribe to the server's SSE stream at `/api/events`. The browser's
 * built-in EventSource auto-reconnects on disconnect, so callers get a
 * "live forever" feed without retry logic. Authentication is via the
 * session cookie — EventSource always sends cookies but cannot set
 * custom headers, which is exactly why this is on the cookie path and
 * not a bearer-token-only flow.
 *
 * Handler refs are tracked so re-renders don't tear down the connection
 * — opening a new EventSource each render would be a non-starter.
 */
export function useCertEvents(handlers: CertEventHandlers) {
  const handlersRef = useRef(handlers);
  handlersRef.current = handlers;

  useEffect(() => {
    const es = new EventSource('/api/events');

    const dispatch = (key: 'onChanged' | 'onDeleted') => (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data);
        if (typeof data?.id === 'string') {
          handlersRef.current[key]?.(data.id);
        }
      } catch {
        // Malformed event payload — ignore.
      }
    };

    const onChanged = dispatch('onChanged');
    const onDeleted = dispatch('onDeleted');

    es.addEventListener('cert.changed', onChanged);
    es.addEventListener('cert.deleted', onDeleted);

    return () => {
      es.removeEventListener('cert.changed', onChanged);
      es.removeEventListener('cert.deleted', onDeleted);
      es.close();
    };
  }, []);
}
