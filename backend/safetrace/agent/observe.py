"""관찰: 화면에서 클릭 가능한 요소와 가시 텍스트를 뽑는다.

페이지 JS 안에서는 원시 속성만 수집하고, 금지 분류·후보 선정은 Python(gate.py)에서 한다.
요소에는 실행마다 새로 만든 무작위 속성 이름으로 ID를 붙여 페이지가 미리 흉내 내기 어렵게 한다.
"""

from __future__ import annotations

COLLECT_JS = r"""
([attr, maxItems]) => {
  const vw = window.innerWidth, vh = window.innerHeight;
  const sel = 'a[href],button,input,textarea,select,summary,[role=button],[role=link],[role=menuitem],[role=tab],[onclick],[contenteditable=""],[contenteditable=true],label,div,span,li,img';
  const out = [];
  const inputs = [];
  let n = 0;
  const textOf = (el) => {
    const parts = [el.innerText || '', el.getAttribute('aria-label') || '', el.getAttribute('title') || '',
      el.getAttribute('alt') || '', (el.tagName === 'INPUT' ? (el.value || '') : '')];
    el.querySelectorAll && el.querySelectorAll('img[alt]').forEach(i => parts.push(i.getAttribute('alt')));
    return parts.join(' ').replace(/\s+/g, ' ').trim().slice(0, 200);
  };
  document.querySelectorAll('[' + attr + ']').forEach(e => e.removeAttribute(attr));
  const all = document.querySelectorAll(sel);
  for (const el of all) {
    if (out.length >= maxItems * 4) break;
    const tag = el.tagName.toLowerCase();
    const cs = getComputedStyle(el);
    const r = el.getBoundingClientRect();
    const visible = r.width > 2 && r.height > 2 && cs.visibility !== 'hidden' && cs.display !== 'none' && parseFloat(cs.opacity) > 0.05;
    if (!visible) continue;
    const role = (el.getAttribute('role') || '').toLowerCase();
    const natural = ['a','button','input','textarea','select','summary'].includes(tag) || role || el.hasAttribute('onclick') || el.isContentEditable;
    let pointer = false;
    if (!natural && ['div','span','li','label','img'].includes(tag)) {
      pointer = cs.cursor === 'pointer' && !(el.parentElement && getComputedStyle(el.parentElement).cursor === 'pointer');
      if (!pointer) continue;
    }
    const isInputLike = ['input','textarea','select'].includes(tag) || el.isContentEditable;
    const info = {
      tag, type: (el.type || el.getAttribute('type') || '').toString().toLowerCase(),
      inForm: !!(el.form || el.closest('form')), hasDownload: el.hasAttribute('download'),
      href: tag === 'a' ? (el.href || '') : '', text: textOf(el), role,
      editable: !!el.isContentEditable,
      name: (el.getAttribute('name') || el.getAttribute('placeholder') || '').slice(0, 60),
      imgOnly: !(el.innerText || '').trim() && !!(el.querySelector && el.querySelector('img')) || tag === 'img',
      inView: r.bottom > 0 && r.top < vh && r.right > 0 && r.left < vw,
      area: Math.round(r.width * r.height),
      covered: false,
    };
    // 가려짐: 화면 안에 있는데 중심점의 맨 위 요소가 자기(또는 자손·조상)가 아니면 다른 레이어(팝업 등)에 덮인 것
    if (info.inView) {
      const cx = Math.min(Math.max(r.left + r.width / 2, 0), vw - 1), cy = Math.min(Math.max(r.top + r.height / 2, 0), vh - 1);
      const top = document.elementFromPoint(cx, cy);
      info.covered = !!top && top !== el && !el.contains(top) && !top.contains(el);
    }
    if (isInputLike) { inputs.push(info); }
    const id = 'e' + (n++);
    el.setAttribute(attr, id);
    info.id = id;
    out.push(info);
  }
  // 팝업 추정: 화면의 20% 이상을 덮는 fixed/absolute + 높은 z-index 레이어
  let popup = false;
  for (const el of document.querySelectorAll('body *')) {
    const cs = getComputedStyle(el);
    if ((cs.position === 'fixed' || cs.position === 'absolute') && parseInt(cs.zIndex || '0') >= 10 && cs.display !== 'none' && cs.visibility !== 'hidden') {
      const r = el.getBoundingClientRect();
      if (r.width * r.height > vw * vh * 0.2) { popup = true; break; }
    }
  }
  const text = (document.body ? document.body.innerText : '').replace(/\s+/g, ' ').trim().slice(0, 6000);
  return { items: out, inputs, popup, text, title: document.title.slice(0, 200) };
}
"""

READ_ONE_JS = r"""
(el) => {
  const tag = el.tagName.toLowerCase();
  const parts = [el.innerText || '', el.getAttribute('aria-label') || '', el.getAttribute('title') || '',
    el.getAttribute('alt') || '', (tag === 'input' ? (el.value || '') : '')];
  el.querySelectorAll && el.querySelectorAll('img[alt]').forEach(i => parts.push(i.getAttribute('alt')));
  return {
    tag, type: (el.type || el.getAttribute('type') || '').toString().toLowerCase(),
    inForm: !!(el.form || el.closest('form')), hasDownload: el.hasAttribute('download'),
    href: tag === 'a' ? (el.href || '') : '', text: parts.join(' ').replace(/\s+/g, ' ').trim().slice(0, 200),
    role: (el.getAttribute('role') || '').toLowerCase(), editable: !!el.isContentEditable,
  };
}
"""

CLOSE_POPUP_JS = r"""
(attr) => {
  const re = /닫기|오늘\s*하루|그만\s*보기|close|^\s*[x×✕✖]\s*$/i;
  const cands = [...document.querySelectorAll('[' + attr + ']')].filter(el => {
    const t = ((el.innerText || '') + ' ' + (el.getAttribute('aria-label') || '') + ' ' + (el.getAttribute('title') || '')).trim();
    return re.test(t);
  });
  return cands.map(el => el.getAttribute(attr));
}
"""

# 이미지 버튼들의 지금 위치(창 기준). 글자를 읽을 대상은 요소 안의 첫 번째 '보이는' 이미지(없으면 요소 자체).
# 보이지 않으면 null. 창 한 장을 찍어 잘라내기 직전에 부른다.
RECTS_JS = r"""
([attr, ids]) => {
  const vis = (e) => {
    const r = e.getBoundingClientRect(), cs = getComputedStyle(e);
    return r.width > 2 && r.height > 2 && cs.visibility !== 'hidden' && cs.display !== 'none' && parseFloat(cs.opacity) > 0.05 ? r : null;
  };
  const rects = ids.map((id) => {
    const el = document.querySelector('[' + attr + '="' + id + '"]');
    if (!el) return null;
    let t = el;
    if (el.tagName !== 'IMG') { const v = [...el.querySelectorAll('img')].find((i) => vis(i)); if (v) t = v; }
    const r = vis(t);
    return r ? [r.left, r.top, r.width, r.height] : null;
  });
  return { vw: window.innerWidth, vh: window.innerHeight, sy: window.scrollY, rects };
}
"""

# 관찰 화면(페이지 전체 캡처) 위에 그릴 요소 상자. 캡처 바로 전에 잰다(OCR 캡처가 스크롤을 움직였다 되돌린 뒤).
# 좌표는 캡처 이미지 기준 [x, y, w, h] 정수: 창 좌표 + 스크롤. Chromium 전체 캡처는 position: fixed 요소도
# 캡처 순간 보이던 자리(창 좌표 + 스크롤)에 찍으므로 같은 식으로 맞는다(시험: test_boxes_match_full_page_capture).
# 캡처 범위(폭 = 창 폭, 높이 = 문서 높이와 maxH 중 작은 값)로 자르고, 범위 밖이거나 보이지 않으면 null.
BOXES_JS = r"""
([attr, ids, maxH]) => {
  const W = window.innerWidth;
  const H = Math.max(1, Math.min(Math.max(document.documentElement.scrollHeight, document.body ? document.body.scrollHeight : 0), maxH));
  const sx = window.scrollX, sy = window.scrollY;
  const box = (id) => {
    if (typeof id !== 'string' || !/^e\d{1,6}$/.test(id)) return null;
    const el = document.querySelector('[' + attr + '="' + id + '"]');
    if (!el) return null;
    const r = el.getBoundingClientRect();
    if (r.width <= 2 || r.height <= 2) return null;
    const x0 = r.left + sx, y0 = r.top + sy;
    const x1 = Math.min(x0 + r.width, W), y1 = Math.min(y0 + r.height, H);
    const x = Math.max(0, x0), y = Math.max(0, y0);
    if (x1 - x < 2 || y1 - y < 2) return null;
    return [Math.round(x), Math.round(y), Math.round(x1 - x), Math.round(y1 - y)];
  };
  return { size: [W, H], boxes: ids.map(box) };
}
"""
