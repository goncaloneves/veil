import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { bytesFromBase64, decodeBytes, looksMisdecoded, readText } from '../src/core/text.ts'
import { fake, seeded } from './helpers.ts'

const TOKEN = fake.hex(seeded(50), 32)
const TEXT = `API_TOKEN=${TOKEN}\r\nNAME=café\r\n`

function utf16le(text: string, bom: boolean): Uint8Array {
  const body = Buffer.from(text, 'utf16le')
  return new Uint8Array(bom ? Buffer.concat([Buffer.from([0xff, 0xfe]), body]) : body)
}

function utf16be(text: string): Uint8Array {
  const le = Buffer.from(text, 'utf16le')
  const be = Buffer.alloc(le.length)
  for (let i = 0; i + 1 < le.length; i += 2) {
    be[i] = le[i + 1] ?? 0
    be[i + 1] = le[i] ?? 0
  }
  return new Uint8Array(Buffer.concat([Buffer.from([0xfe, 0xff]), be]))
}

describe('text', () => {
  it('decodes UTF-16 with and without a byte order mark, and UTF-8 with one', () => {
    assert.equal(decodeBytes(utf16le(TEXT, true)), TEXT)
    assert.equal(decodeBytes(utf16le(TEXT, false)), TEXT)
    assert.equal(decodeBytes(utf16be(TEXT)), TEXT)
    assert.equal(decodeBytes(new Uint8Array(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(TEXT)]))), TEXT)
    assert.equal(decodeBytes(new Uint8Array(Buffer.from(TEXT))), TEXT)
  })

  it('keeps every byte of text that is not valid UTF-8', () => {
    const latin1 = new Uint8Array([0x41, 0x3d, 0xe9, 0x74, 0xe9])
    assert.equal(decodeBytes(latin1), 'A=été')
  })

  it('decodes base64 the same way as the platform', () => {
    const bytes = utf16le(TEXT, true)
    assert.deepEqual(bytesFromBase64(Buffer.from(bytes).toString('base64')), bytes)
  })

  it('tells when UTF-8 text was really UTF-16', () => {
    assert.equal(looksMisdecoded(Buffer.from(utf16le(TEXT, true)).toString('utf8')), true)
    assert.equal(looksMisdecoded(Buffer.from(utf16le(TEXT, false)).toString('utf8')), true)
    assert.equal(looksMisdecoded(TEXT), false)
    assert.equal(looksMisdecoded('a\0b'), false)
  })

  it('reads bytes only when the text was misdecoded', async () => {
    let byteReads = 0
    const bytes = utf16le(TEXT, true)
    const read = (text: string) => readText(async () => text, async () => (byteReads++, Buffer.from(bytes).toString('base64')))
    assert.equal(await read(TEXT), TEXT)
    assert.equal(await read(`﻿${TEXT}`), TEXT)
    assert.equal(byteReads, 0)
    assert.equal(await read(Buffer.from(bytes).toString('utf8')), TEXT)
    assert.equal(byteReads, 1)
  })
})
