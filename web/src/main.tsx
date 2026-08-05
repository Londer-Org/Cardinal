import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App } from '@/App'
import '@/index.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Authentication state must never be served stale: a revoked session
      // should stop looking valid the moment the user touches the page.
      staleTime: 0,
      refetchOnWindowFocus: true,
      retry: false,
    },
  },
})

const container = document.getElementById('root')
if (!container) {
  throw new Error('root element missing from index.html')
}

createRoot(container).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
)
