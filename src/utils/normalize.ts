import { basename } from "node:path";

export function normalizeBinaryName(name: string): string {
  return name
    .toLowerCase()
    .replace(/\.exe$|\.dll$|\.sys$|\.ps1$|\.cmd$|\.bat$|\.vbs$|\.js$|\.msc$/, "")
    .replace(/\d+(\.\d+)*$/, "")
    .replace(/\.basic$|\.tiny$/, "")
    .trim();
}

export function extractBinaryName(pathOrName: string): string {
  return normalizeBinaryName(basename(pathOrName));
}

export const BINARY_ALIASES: Record<string, string[]> = {
  python: ["python2", "python3", "python3.8", "python3.9", "python3.10", "python3.11", "python3.12", "python.exe"],
  vim: ["vim.basic", "vim.tiny", "vi", "nvim", "vimdiff"],
  curl: ["curl.exe"],
  wget: ["wget.exe"],
  ssh: ["ssh.exe", "openssh"],
  perl: ["perl5", "perl.exe"],
  ruby: ["ruby3", "ruby.exe"],
  node: ["nodejs", "node.exe"],
  nc: ["ncat", "netcat", "nc.openbsd", "nc.traditional"],
  bash: ["bash.exe", "sh"],
  php: ["php7", "php8", "php.exe"],
  tar: ["tar.exe", "gtar"],
  find: ["gfind"],
  awk: ["gawk", "mawk", "nawk"],
  sed: ["gsed"],
  zip: ["zip.exe"],
  certutil: ["certutil.exe"],
  powershell: ["powershell.exe", "pwsh", "pwsh.exe"],
  cmd: ["cmd.exe"],
  mshta: ["mshta.exe"],
  rundll32: ["rundll32.exe"],
  regsvr32: ["regsvr32.exe"],
  wmic: ["wmic.exe"],
  cscript: ["cscript.exe"],
  wscript: ["wscript.exe"],
  msiexec: ["msiexec.exe"],
  schtasks: ["schtasks.exe"],
  bitsadmin: ["bitsadmin.exe"],
};

export function getAliases(binaryName: string): string[] {
  const norm = normalizeBinaryName(binaryName);

  // Direct match
  if (BINARY_ALIASES[norm]) return BINARY_ALIASES[norm];

  // Reverse match (find the canonical name for this alias)
  for (const [canonical, aliases] of Object.entries(BINARY_ALIASES)) {
    if (aliases.some(a => normalizeBinaryName(a) === norm)) {
      return [canonical, ...aliases.filter(a => normalizeBinaryName(a) !== norm)];
    }
  }

  return [];
}

export function addToIndex<K, V>(map: Map<K, V[]>, key: K, value: V): void {
  const arr = map.get(key);
  if (arr) arr.push(value);
  else map.set(key, [value]);
}

export function deduplicateById<T extends { id: string }>(items: T[]): T[] {
  const seen = new Set<string>();
  return items.filter(item => {
    if (seen.has(item.id)) return false;
    seen.add(item.id);
    return true;
  });
}
