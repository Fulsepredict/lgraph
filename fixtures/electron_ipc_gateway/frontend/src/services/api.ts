export async function appFetch(subPath: string, options?: { method?: string }) {
  return (window as any).electronAPI.apiRequest({
    path: subPath,
    method: options?.method ?? 'GET',
  });
}

export async function triggerProfileCheck(id: number) {
  return appFetch(`/profiles/${id}/check`, { method: 'POST' });
}
