export function getLogoUrl(websiteUrl: string): string {
  let domain = websiteUrl.trim();
  domain = domain.replace(/^https?:\/\//, "");
  domain = domain.replace(/\/.*$/, "");
  domain = domain.replace(/^www\./, "");

  if (!domain) return "";

  return `https://www.google.com/s2/favicons?sz=64&domain=${encodeURIComponent(domain)}`;
}

export function extractDomain(url: string): string {
  let domain = url.trim();
  domain = domain.replace(/^https?:\/\//, "");
  domain = domain.replace(/\/.*$/, "");
  domain = domain.replace(/^www\./, "");
  return domain;
}
