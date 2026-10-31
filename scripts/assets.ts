import { mkdir, writeFile } from 'node:fs/promises'

const OUT = new URL('../docs/assets/', import.meta.url)

const SANS = "ui-sans-serif, -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"
const MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace"

type Theme = Record<'text' | 'muted' | 'card' | 'border' | 'panel' | 'placeholder' | 'secret' | 'arrow' | 'boundary' | 'chip' | 'chipText' | 'bg', string>

const THEMES: Record<'light' | 'dark', Theme> = {
  light: {
    text: '#0F172A',
    muted: '#475569',
    card: '#F8FAFC',
    border: '#CBD5E1',
    panel: '#FFFFFF',
    placeholder: '#6D28D9',
    secret: '#B45309',
    arrow: '#64748B',
    boundary: '#94A3B8',
    chip: '#EEF2FF',
    chipText: '#3730A3',
    bg: '#FFFFFF',
  },
  dark: {
    text: '#E2E8F0',
    muted: '#94A3B8',
    card: '#111827',
    border: '#334155',
    panel: '#0B1220',
    placeholder: '#C4B5FD',
    secret: '#FBBF24',
    arrow: '#94A3B8',
    boundary: '#475569',
    chip: '#1E1B4B',
    chipText: '#C7D2FE',
    bg: '#0D1117',
  },
}

function glyph(x: number, y: number, size: number, id: string, plate = `url(#g${id})`): string {
  return `<g transform="translate(${x} ${y}) scale(${size / 120})">
    <defs><linearGradient id="g${id}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#6366F1"/><stop offset="1" stop-color="#8B5CF6"/></linearGradient></defs>
    <rect x="0" y="0" width="120" height="120" rx="30" fill="${plate}"/>
    <path d="M44 30 H32 V90 H44" fill="none" stroke="#FFFFFF" stroke-width="9" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="M76 30 H88 V90 H76" fill="none" stroke="#FFFFFF" stroke-width="9" stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="47" cy="60" r="6" fill="#FFFFFF"/><circle cx="60" cy="60" r="6" fill="#FFFFFF"/><circle cx="73" cy="60" r="6" fill="#FFFFFF"/>
  </g>`
}

type TextOptions = { anchor?: string; size?: number; color?: string; weight?: number; family?: string }

function text(c: Theme, x: number, y: number, body: string, o: TextOptions = {}): string {
  return `<text x="${x}" y="${y}" text-anchor="${o.anchor ?? 'middle'}" font-family="${o.family ?? SANS}" font-size="${o.size ?? 14}" font-weight="${o.weight ?? 500}" fill="${o.color ?? c.muted}">${body}</text>`
}

function arrow(c: Theme, x1: number, y1: number, x2: number, y2: number): string {
  return `<path d="M${x1} ${y1} L${x2} ${y2}" fill="none" stroke="${c.arrow}" stroke-width="2.2" marker-end="url(#head)"/>`
}

function card(c: Theme, x: number, y: number, w: number, h: number, title: string, lines: readonly string[]): string {
  return [
    `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="12" fill="${c.card}" stroke="${c.border}"/>`,
    text(c, x + 16, y + 26, title, { anchor: 'start', size: 15, color: c.text, weight: 600 }),
    ...lines.map((line, i) => text(c, x + 16, y + 50 + i * 21, line, { anchor: 'start', size: 13.5, weight: 400, family: MONO })),
  ].join('\n  ')
}

function chip(c: Theme, x: number, y: number, body: string): string {
  return `<rect x="${x}" y="${y}" width="114" height="30" rx="15" fill="${c.chip}"/>${text(c, x + 57, y + 20, body, { size: 13, color: c.chipText })}`
}

function logo(c: Theme): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="360" height="120" viewBox="0 0 360 120" role="img" aria-label="veil">
  ${glyph(0, 0, 120, 'logo')}
  <text x="146" y="88" font-family="${SANS}" font-size="84" font-weight="700" letter-spacing="-3" fill="${c.text}">veil</text>
</svg>
`
}

function icon(): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 120 120" role="img" aria-label="veil">
  ${glyph(0, 0, 120, 'icon')}
</svg>
`
}

function architecture(c: Theme): string {
  const mono = { anchor: 'start', size: 14, weight: 500, family: MONO, color: c.text }
  const parts = [
    `<defs><linearGradient id="veilbox" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#6366F1"/><stop offset="1" stop-color="#8B5CF6"/></linearGradient><marker id="head" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="${c.arrow}"/></marker></defs>`,
    `<rect x="0" y="0" width="1200" height="600" rx="16" fill="${c.bg}"/>`,
    `<rect x="20" y="20" width="850" height="560" rx="18" fill="none" stroke="${c.boundary}" stroke-width="1.6" stroke-dasharray="7 6"/>`,
    text(c, 44, 50, 'YOUR MACHINE', { anchor: 'start', size: 13, weight: 700 }),
    text(c, 156, 50, '· nothing leaves it unmasked', { anchor: 'start', size: 13, weight: 400 }),
    card(c, 44, 76, 270, 112, 'Your secret files', ['.env  .env.local  *.env', '~/.aws  ~/.ssh  ~/.npmrc', 'gh  docker  kube  netrc…']),
    card(c, 44, 204, 270, 70, 'Your environment', ['GITHUB_TOKEN  OPENAI_API_KEY…']),
    `<rect x="44" y="300" width="270" height="256" rx="12" fill="${c.card}" stroke="${c.border}"/>`,
    text(c, 60, 326, 'Your coding agent', { anchor: 'start', size: 15, color: c.text, weight: 600 }),
    text(c, 60, 346, 'everything it sends or stores', { anchor: 'start', size: 13, weight: 400 }),
    ...['prompts', 'tool results', 'file reads', 'errors', 'system prompt', 'CLAUDE.md'].map((body, i) => chip(c, 60 + (i % 2) * 122, 366 + Math.floor(i / 2) * 44, body)),
    text(c, 60, 528, '@-mentions · skills · messages', { anchor: 'start', size: 12.5, weight: 400 }),
    `<rect x="392" y="150" width="216" height="300" rx="20" fill="url(#veilbox)"/>`,
    glyph(470, 176, 60, 'arch', 'rgba(255,255,255,0.16)'),
    text(c, 500, 272, 'veil', { size: 34, color: '#FFFFFF', weight: 700 }),
    text(c, 500, 306, 'your real values', { size: 14, color: '#EDE9FE' }),
    text(c, 500, 328, '+ gitleaks pattern rules', { size: 14, color: '#EDE9FE' }),
    `<line x1="424" y1="352" x2="576" y2="352" stroke="#FFFFFF" stroke-opacity="0.35"/>`,
    text(c, 500, 380, 'masks what goes out', { size: 14, color: '#FFFFFF', weight: 600 }),
    text(c, 500, 404, 'restores what comes back', { size: 14, color: '#FFFFFF', weight: 600 }),
    text(c, 500, 428, 'only where it belongs', { size: 12.5, color: '#EDE9FE', weight: 400 }),
    arrow(c, 314, 150, 390, 222),
    text(c, 352, 172, 'read once', { size: 12.5 }),
    arrow(c, 314, 240, 390, 262),
    arrow(c, 314, 430, 390, 360),
    `<rect x="910" y="96" width="270" height="200" rx="14" fill="${c.panel}" stroke="${c.border}"/>`,
    text(c, 926, 124, 'The model and transcript', { anchor: 'start', size: 15, color: c.text, weight: 600 }),
    text(c, 926, 144, 'never see a real value', { anchor: 'start', size: 13, weight: 400 }),
    text(c, 926, 186, 'API_TOKEN=', mono),
    text(c, 926, 208, '[veil:API_TOKEN]', { ...mono, color: c.placeholder, weight: 600 }),
    text(c, 926, 244, 'DATABASE_URL=', mono),
    text(c, 926, 266, '[veil:DATABASE_URL]', { ...mono, color: c.placeholder, weight: 600 }),
    arrow(c, 610, 220, 906, 196),
    text(c, 760, 192, 'masked', { size: 13, weight: 600, color: c.placeholder }),
    arrow(c, 906, 262, 610, 300),
    text(c, 760, 304, 'edits with placeholders', { size: 12.5 }),
    `<rect x="640" y="404" width="210" height="152" rx="12" fill="${c.card}" stroke="${c.border}"/>`,
    text(c, 656, 430, 'Your files', { anchor: 'start', size: 15, color: c.text, weight: 600 }),
    text(c, 656, 466, 'API_TOKEN=', mono),
    text(c, 656, 488, '4f9c2a1b8e…', { ...mono, color: c.secret, weight: 600 }),
    text(c, 656, 520, 'real value back only in the', { anchor: 'start', size: 12, weight: 400 }),
    text(c, 656, 538, 'file it came from', { anchor: 'start', size: 12, weight: 400 }),
    arrow(c, 560, 452, 638, 478),
  ]
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="600" viewBox="0 0 1200 600" role="img" aria-label="How veil works: it reads your secret files and environment once, masks everything your coding agent sends to the model, and restores real values only into the file they came from">
  ${parts.join('\n  ')}
</svg>
`
}

await mkdir(OUT, { recursive: true })
for (const [name, theme] of Object.entries(THEMES)) {
  await writeFile(new URL(`logo-${name}.svg`, OUT), logo(theme))
  await writeFile(new URL(`architecture-${name}.svg`, OUT), architecture(theme))
}
await writeFile(new URL('icon.svg', OUT), icon())
console.log('docs/assets written; render icon.png from icon.svg at 1024 px')
