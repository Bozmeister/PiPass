export function getLogoUrl(websiteUrl: string): string {
  return "";
}

export function extractDomain(url: string): string {
  let domain = url.trim();
  domain = domain.replace(/^https?:\/\//, "");
  domain = domain.replace(/\/.*$/, "");
  domain = domain.replace(/^www\./, "");
  return domain;
}
