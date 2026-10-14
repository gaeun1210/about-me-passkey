// 아주 작은 CBOR 해석기 (WebAuthn에 필요한 만큼만)
// 패스키 등록 응답(attestationObject)과 공개키(COSE 형식)가 CBOR라는 이진 형식으로 오기 때문에 필요합니다.

export function decodeFirst(buf, offset = 0) {
  return readItem(buf, offset);
}

function readLength(buf, pos, info) {
  if (info < 24) return [info, pos];
  if (info === 24) return [buf[pos], pos + 1];
  if (info === 25) return [buf.readUInt16BE(pos), pos + 2];
  if (info === 26) return [buf.readUInt32BE(pos), pos + 4];
  if (info === 27) {
    const big = buf.readBigUInt64BE(pos);
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('CBOR: 너무 큰 길이');
    return [Number(big), pos + 8];
  }
  throw new Error('CBOR: 길이를 알 수 없는 항목은 지원하지 않습니다');
}

function readItem(buf, pos) {
  if (pos >= buf.length) throw new Error('CBOR: 데이터가 끝났습니다');
  const first = buf[pos++];
  const major = first >> 5;
  const info = first & 0x1f;

  if (major === 7) {
    if (info === 20) return [false, pos];
    if (info === 21) return [true, pos];
    if (info === 22) return [null, pos];
    if (info === 23) return [undefined, pos];
    if (info === 25) return [readHalf(buf.readUInt16BE(pos)), pos + 2];
    if (info === 26) return [buf.readFloatBE(pos), pos + 4];
    if (info === 27) return [buf.readDoubleBE(pos), pos + 8];
    throw new Error('CBOR: 지원하지 않는 단순 값');
  }

  let len;
  [len, pos] = readLength(buf, pos, info);

  switch (major) {
    case 0: return [len, pos];
    case 1: return [-1 - len, pos];
    case 2: {
      if (pos + len > buf.length) throw new Error('CBOR: 바이트 길이 초과');
      return [Buffer.from(buf.subarray(pos, pos + len)), pos + len];
    }
    case 3: {
      if (pos + len > buf.length) throw new Error('CBOR: 문자열 길이 초과');
      return [buf.subarray(pos, pos + len).toString('utf8'), pos + len];
    }
    case 4: {
      const arr = [];
      for (let i = 0; i < len; i++) { let v; [v, pos] = readItem(buf, pos); arr.push(v); }
      return [arr, pos];
    }
    case 5: {
      const map = new Map();
      for (let i = 0; i < len; i++) {
        let k, v;
        [k, pos] = readItem(buf, pos);
        [v, pos] = readItem(buf, pos);
        map.set(k, v);
      }
      return [map, pos];
    }
    case 6: { // 태그는 내용만 꺼냅니다
      return readItem(buf, pos);
    }
  }
  throw new Error('CBOR: 알 수 없는 형식');
}

function readHalf(h) {
  const s = (h & 0x8000) ? -1 : 1;
  const e = (h >> 10) & 0x1f;
  const f = h & 0x3ff;
  if (e === 0) return s * Math.pow(2, -14) * (f / 1024);
  if (e === 31) return f ? NaN : s * Infinity;
  return s * Math.pow(2, e - 15) * (1 + f / 1024);
}
