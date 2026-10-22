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
  const full = document.body ? document.body.innerText : '';
  const text = full.replace(/\s+/g, ' ').trim().slice(0, 6000);
  // 연관 후보용 링크: 클릭 후보와 별개로 화면의 모든 a[href] 의 http·https 절대 주소(보이지 않는 링크 포함, 최대 200개).
  // 판단 모델에는 보내지 않는다(Python 이 다시 검사한다)
  const links = [];
  for (const a of document.querySelectorAll('a[href]')) {
    if (links.length >= 200) break;
    const href = String(a.href || '');
    if (href.length > 2048 || !/^https?:\/\//i.test(href)) continue;
    const r = a.getBoundingClientRect(), cs = getComputedStyle(a);
    const shown = r.width > 2 && r.height > 2 && cs.visibility !== 'hidden' && cs.display !== 'none';
    // 금지 분류(결제·다운로드·로그인 등)는 Python 이 클릭 후보와 같은 규칙으로 한다. 글자도 클릭 후보와 같게 화면 글자·
    // aria-label·title·이미지 alt 를 모두 합친다(하나만 읽으면 aria-label 에만 '결제'를 둔 링크가 빠져나간다, Codex 지적)
    const imgOnly = !(a.innerText || '').trim() && !!a.querySelector('img');
    links.push({ href, text: textOf(a), visible: shown, hasDownload: a.hasAttribute('download'),
                 inForm: !!a.closest('form'), imgOnly });
  }
  // 운영 정보·키트 지문(agent/intel.py): 연락 링크(텔레그램·카톡·tel: 등), 입력 양식이 보내는 곳, 문의·입금 같은 말
  // 둘레의 글자 조각, 화면 요소 순서(태그·깊이)와 같은 출처의 js·css 경로. 판단 모델에는 보내지 않는다(Python 이
  // 정해진 모양만 뽑는다). 어느 하나가 실패해도 관찰은 계속한다
  const contacts = [], forms = [], snips = [], kit = { dom: '', n: 0, res: [] };
  try {
    const re = /^(tel|sms|tg):|^https?:\/\/(?:www\.)?(?:t\.me|telegram\.me|telegram\.dog|open\.kakao\.com|pf\.kakao\.com|qr\.kakao\.com|line\.me|wa\.me|api\.whatsapp\.com|discord\.gg|discord\.com)\//i;
    let seen = 0;
    for (const a of document.querySelectorAll('a[href]')) {
      if (contacts.length >= 60 || ++seen > 5000) break;
      const h = String(a.href || '');
      if (h.length <= 2048 && re.test(h)) contacts.push(h);
    }
  } catch (e) {}
  try {
    for (const f of document.querySelectorAll('form')) {
      if (forms.length >= 10) break;
      // f.action·f.method 는 이름이 action 인 입력칸으로 바꿔치기된다(DOM clobbering): 속성을 읽어 직접 푼다
      const raw = f.getAttribute('action');
      let action = '';
      try { action = raw ? new URL(raw, document.baseURI).href : ''; } catch (e) {}
      forms.push({ action: action.slice(0, 2048), method: String(f.getAttribute('method') || 'get').toLowerCase().slice(0, 8) });
    }
  } catch (e) {}
  try {
    const flat = full.length > 300000 ? full.slice(0, 300000) : full;
    const cue = /텔레그램|텔레|telegram|카카오톡|카톡|문의|상담|고객센터|연락|전화|입금|계좌|은행|예금주/gi;
    let m;
    while ((m = cue.exec(flat)) && snips.length < 40) {
      snips.push(flat.slice(Math.max(0, m.index - 10), m.index + 80).replace(/\s+/g, ' '));
      cue.lastIndex = m.index + 40;
    }
  } catch (e) {}
  try {
    if (document.body) {
      const tw = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT);
      const parts = [];
      for (let el = tw.currentNode; el && parts.length < 3000; el = tw.nextNode()) {
        let d = 0;
        for (let p = el.parentElement; p && d < 32; p = p.parentElement) d++;
        parts.push(el.tagName.toLowerCase() + d);
      }
      kit.dom = parts.join(',');
      kit.n = parts.length;
    }
    const res = new Set();
    for (const el of document.querySelectorAll('script[src],link[href]')) {
      if (res.size >= 100) break;
      try {
        const u = new URL(el.getAttribute('src') || el.getAttribute('href') || '', document.baseURI);
        if (u.origin === location.origin) res.add(u.pathname.slice(0, 200));
      } catch (e) {}
    }
    kit.res = [...res];
  } catch (e) {}
  return { items: out, inputs, popup, text, title: document.title.slice(0, 200), links, contacts, forms, snips, kit };
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
