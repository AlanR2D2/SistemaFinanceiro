/*
 * DateRangePicker — calendário com seleção de intervalo (vanilla JS, sem deps).
 *
 * Uso:
 *   const picker = DateRangePicker.create(containerEl, {
 *     start: '2025-01-01' | null,  // ISO yyyy-mm-dd
 *     end:   '2025-01-18' | null,
 *     onChange(startIso, endIso) { ... }   // opcional
 *   });
 *   picker.getRange();   // { start: 'yyyy-mm-dd' | null, end: 'yyyy-mm-dd' | null }
 *   picker.clear();
 *   picker.destroy();
 */
(function (global) {
  if (global.DateRangePicker) return;

  const PT_MONTHS = [
    'janeiro', 'fevereiro', 'março', 'abril', 'maio', 'junho',
    'julho', 'agosto', 'setembro', 'outubro', 'novembro', 'dezembro'
  ];
  const PT_WEEK = ['dom', 'seg', 'ter', 'qua', 'qui', 'sex', 'sáb'];

  function pad(n) { return String(n).padStart(2, '0'); }

  function fmtISO(d) {
    return d ? `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` : null;
  }

  function fmtBR(d) {
    return d ? `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()}` : '—';
  }

  function parseISO(s) {
    if (!s) return null;
    const m = String(s).match(/^(\d{4})-(\d{2})-(\d{2})/);
    if (!m) return null;
    return new Date(parseInt(m[1], 10), parseInt(m[2], 10) - 1, parseInt(m[3], 10));
  }

  function sameDay(a, b) {
    return a && b &&
      a.getFullYear() === b.getFullYear() &&
      a.getMonth() === b.getMonth() &&
      a.getDate() === b.getDate();
  }

  function dayInRange(d, start, end) {
    if (!d || !start || !end) return false;
    const t = d.getTime();
    const lo = Math.min(start.getTime(), end.getTime());
    const hi = Math.max(start.getTime(), end.getTime());
    return t >= lo && t <= hi;
  }

  function ensureStyles() {
    if (document.getElementById('drp-styles')) return;
    const css = `
.drp-root {
  font-family: inherit;
  user-select: none;
  width: 320px;
  padding: 6px 4px 0 4px;
}
.drp-nav {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 10px;
  padding: 0 4px;
}
.drp-nav-btn {
  width: 30px; height: 30px;
  border-radius: 10px;
  border: 1px solid #e5e7eb;
  background: #fff;
  cursor: pointer;
  font-weight: 700;
  color: #374151;
  font-size: 16px;
  line-height: 1;
}
.drp-nav-btn:hover { background: #f3f4f6; }
.drp-mo-yr { display: flex; align-items: center; gap: 6px; }
.drp-sel {
  font-size: 13px; font-weight: 700;
  border: 1px solid #e5e7eb;
  border-radius: 10px;
  padding: 6px 8px;
  background: #fff;
  color: #111827;
  cursor: pointer;
  outline: none;
}
.drp-sel:focus { border-color: #c7d2fe; box-shadow: 0 0 0 3px rgba(79, 70, 229, .15); }

.drp-week {
  display: grid;
  grid-template-columns: repeat(7, 1fr);
  font-size: 11px;
  color: #6b7280;
  margin-bottom: 4px;
}
.drp-week > div {
  text-align: center;
  padding: 6px 0;
  font-weight: 700;
  text-transform: lowercase;
}

.drp-grid {
  display: grid;
  grid-template-columns: repeat(7, 1fr);
}
.drp-day {
  height: 38px;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  color: #111827;
  position: relative;
}
.drp-day.outside {
  color: #d1d5db;
  cursor: default;
}
.drp-day-num {
  width: 32px; height: 32px;
  display: flex; align-items: center; justify-content: center;
  font-size: 13px;
  border-radius: 999px;
  position: relative;
  z-index: 1;
  transition: background-color .08s ease, color .08s ease;
}
.drp-day:not(.outside):hover .drp-day-num {
  background: #eef2ff;
  color: #4338ca;
}

/* Fundo do range (preenche a célula inteira). Usa ::before pra não atrapalhar o pill. */
.drp-day.in-range::before {
  content: '';
  position: absolute;
  inset: 0;
  background: #eef2ff;
  z-index: 0;
}
.drp-day.range-start::before  { left: 50%; }
.drp-day.range-end::before    { right: 50%; }
.drp-day.range-single::before { display: none; }

/* Selected = início ou fim do range, dark blue */
.drp-day.selected .drp-day-num {
  background: #4f46e5;
  color: #fff;
  font-weight: 800;
}
.drp-day.selected:hover .drp-day-num {
  background: #4338ca;
}

/* Hoje */
.drp-day.today .drp-day-num {
  outline: 1px dashed #c7d2fe;
}

.drp-foot {
  margin-top: 10px;
  padding: 8px 4px 4px 4px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.drp-pills {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}
.drp-pill {
  padding: 3px 10px;
  border-radius: 999px;
  background: #eef2ff;
  color: #4338ca;
  font-weight: 700;
  font-size: 11px;
  border: 1px solid #c7d2fe;
  white-space: nowrap;
}
.drp-hint {
  font-size: 11px;
  color: #6b7280;
}
    `;
    const style = document.createElement('style');
    style.id = 'drp-styles';
    style.textContent = css;
    document.head.appendChild(style);
  }

  function create(container, opts) {
    if (!container) throw new Error('DateRangePicker: container obrigatório');
    opts = opts || {};
    ensureStyles();

    const state = {
      start: parseISO(opts.start),
      end:   parseISO(opts.end),
      hoverDate: null,
      viewYear: 0,
      viewMonth: 0,
    };

    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const anchor = state.start || state.end || today;
    state.viewYear = anchor.getFullYear();
    state.viewMonth = anchor.getMonth();

    const root = document.createElement('div');
    root.className = 'drp-root';
    container.innerHTML = '';
    container.appendChild(root);

    function buildYearOptions() {
      const cur = today.getFullYear();
      const yMin = Math.min(state.viewYear - 5, cur - 5);
      const yMax = Math.max(state.viewYear + 5, cur + 2);
      const out = [];
      for (let y = yMax; y >= yMin; y--) out.push(y);
      return out;
    }

    function render() {
      const y = state.viewYear;
      const m = state.viewMonth;
      const first = new Date(y, m, 1);
      const lastDay = new Date(y, m + 1, 0).getDate();
      const firstDow = first.getDay();

      // Para colorização do range com hover, usa end "efetivo"
      const effStart = state.start;
      let effEnd = state.end;
      if (state.start && !state.end && state.hoverDate) {
        effEnd = state.hoverDate;
      }
      // Normaliza: a "esquerda" e "direita" do range para CSS
      let lo = effStart, hi = effEnd;
      if (lo && hi && lo.getTime() > hi.getTime()) {
        const tmp = lo; lo = hi; hi = tmp;
      }

      let daysHtml = '';

      // Dias do mês anterior (fora)
      const prevLast = new Date(y, m, 0).getDate();
      for (let i = firstDow - 1; i >= 0; i--) {
        daysHtml += `<div class="drp-day outside"><span class="drp-day-num">${prevLast - i}</span></div>`;
      }

      // Dias do mês atual
      for (let d = 1; d <= lastDay; d++) {
        const date = new Date(y, m, d);
        const iso = fmtISO(date);

        const isStart = sameDay(date, effStart);
        const isEnd = sameDay(date, effEnd);
        const isToday = sameDay(date, today);

        let cls = 'drp-day';
        if (isToday) cls += ' today';

        const inRange = dayInRange(date, lo, hi);
        if (inRange) {
          cls += ' in-range';
          const isLoEdge = sameDay(date, lo);
          const isHiEdge = sameDay(date, hi);
          if (isLoEdge && isHiEdge) cls += ' range-single';
          else if (isLoEdge)        cls += ' range-start';
          else if (isHiEdge)        cls += ' range-end';
        }

        // marca como "selected" só se realmente foi clicado (start/end "duro", não hover)
        if (sameDay(date, state.start) || sameDay(date, state.end)) cls += ' selected';

        daysHtml += `<div class="${cls}" data-iso="${iso}"><span class="drp-day-num">${d}</span></div>`;
      }

      // Trailing (fora)
      const cells = firstDow + lastDay;
      const trailing = (7 - (cells % 7)) % 7;
      for (let i = 1; i <= trailing; i++) {
        daysHtml += `<div class="drp-day outside"><span class="drp-day-num">${i}</span></div>`;
      }

      const monthOpts = PT_MONTHS.map((nm, i) =>
        `<option value="${i}" ${i === m ? 'selected' : ''}>${nm}</option>`
      ).join('');

      const yearOpts = buildYearOptions().map(yr =>
        `<option value="${yr}" ${yr === y ? 'selected' : ''}>${yr}</option>`
      ).join('');

      const hint = !state.start
        ? 'Clique em uma data para começar.'
        : (!state.end ? 'Clique no fim do período.' : 'Período selecionado.');

      root.innerHTML = `
        <div class="drp-nav">
          <button class="drp-nav-btn" type="button" data-act="prev" title="Mês anterior">‹</button>
          <div class="drp-mo-yr">
            <select class="drp-sel" data-act="month">${monthOpts}</select>
            <select class="drp-sel" data-act="year">${yearOpts}</select>
          </div>
          <button class="drp-nav-btn" type="button" data-act="next" title="Próximo mês">›</button>
        </div>
        <div class="drp-week">
          ${PT_WEEK.map(w => `<div>${w}</div>`).join('')}
        </div>
        <div class="drp-grid">
          ${daysHtml}
        </div>
        <div class="drp-foot">
          <div class="drp-pills">
            <span class="drp-pill">Início: ${fmtBR(state.start)}</span>
            <span class="drp-pill">Fim: ${fmtBR(state.end)}</span>
          </div>
          <div class="drp-hint">${hint}</div>
        </div>
      `;
    }

    // Click — navegação + seleção
    root.addEventListener('click', (e) => {
      const tgt = e.target;

      const prev = tgt.closest('[data-act="prev"]');
      const next = tgt.closest('[data-act="next"]');
      if (prev) {
        state.viewMonth--;
        if (state.viewMonth < 0) { state.viewMonth = 11; state.viewYear--; }
        render();
        return;
      }
      if (next) {
        state.viewMonth++;
        if (state.viewMonth > 11) { state.viewMonth = 0; state.viewYear++; }
        render();
        return;
      }

      const dayEl = tgt.closest('.drp-day');
      if (dayEl && !dayEl.classList.contains('outside')) {
        const d = parseISO(dayEl.dataset.iso);
        if (!d) return;

        if (!state.start || (state.start && state.end)) {
          // Recomeça a seleção
          state.start = d;
          state.end = null;
        } else {
          // Já tem start, falta end
          state.end = d;
          if (state.end.getTime() < state.start.getTime()) {
            const tmp = state.start;
            state.start = state.end;
            state.end = tmp;
          }
        }
        state.hoverDate = null;
        render();
        if (opts.onChange) {
          opts.onChange(fmtISO(state.start), fmtISO(state.end));
        }
      }
    });

    // Selects mês/ano
    root.addEventListener('change', (e) => {
      const tgt = e.target;
      if (tgt.matches('[data-act="month"]')) {
        state.viewMonth = parseInt(tgt.value, 10);
        render();
      } else if (tgt.matches('[data-act="year"]')) {
        state.viewYear = parseInt(tgt.value, 10);
        render();
      }
    });

    // Hover preview enquanto escolhe o fim
    root.addEventListener('mouseover', (e) => {
      const dayEl = e.target.closest('.drp-day');
      if (!dayEl || dayEl.classList.contains('outside')) return;
      if (!state.start || state.end) return;
      const d = parseISO(dayEl.dataset.iso);
      if (sameDay(d, state.hoverDate)) return;
      state.hoverDate = d;
      render();
    });

    root.addEventListener('mouseleave', () => {
      if (state.hoverDate) {
        state.hoverDate = null;
        render();
      }
    });

    render();

    return {
      getRange() {
        return { start: fmtISO(state.start), end: fmtISO(state.end) };
      },
      clear() {
        state.start = null;
        state.end = null;
        state.hoverDate = null;
        render();
      },
      destroy() {
        if (root.parentNode) root.parentNode.removeChild(root);
      }
    };
  }

  global.DateRangePicker = { create };
})(window);
