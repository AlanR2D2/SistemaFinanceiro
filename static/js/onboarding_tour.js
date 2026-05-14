/*
 * Onboarding Tour — Sistema Financeiro
 *
 * Tours modulares por seção, navegáveis via botão "?" no header.
 * Auto-dispara o fluxo de boas-vindas no PRIMEIRO login do usuário.
 *
 * Depende de:
 *   - driver.js (carregado por CDN em base.html)
 *   - window.SF_ONBOARDING (definido inline em base.html)
 */
(function (global) {
  if (global.SistemaTour) return;

  /* ------------ Helpers de baixo nível ------------ */

  function getDriver() {
    // Driver.js v1.x IIFE: expõe `window.driver.js.driver()`.
    if (global.driver && global.driver.js && typeof global.driver.js.driver === 'function') {
      return global.driver.js.driver;
    }
    if (typeof global.driver === 'function') return global.driver;
    return null;
  }

  function $(sel) { return document.querySelector(sel); }

  function waitFor(sel, timeoutMs) {
    timeoutMs = timeoutMs || 3000;
    return new Promise((resolve) => {
      const start = Date.now();
      const tick = () => {
        const el = document.querySelector(sel);
        if (el) return resolve(el);
        if (Date.now() - start > timeoutMs) return resolve(null);
        setTimeout(tick, 100);
      };
      tick();
    });
  }

  function isMobile() { return window.innerWidth < 768; }

  function canSeeAdmin() {
    const h = (global.SF_ONBOARDING && global.SF_ONBOARDING.hierarquia) || '';
    return ['admin', 'financeiro', 'gestor', 'administrador', 'master'].indexOf(h) !== -1;
  }

  function showToast(msg) {
    let t = document.getElementById('sfTourToast');
    if (!t) {
      t = document.createElement('div');
      t.id = 'sfTourToast';
      t.style.cssText = `
        position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%);
        background: #111827; color: #fff; padding: 12px 18px; border-radius: 12px;
        font-size: 14px; font-weight: 600; z-index: 999999; box-shadow: 0 8px 30px rgba(0,0,0,.3);
        opacity: 0; transition: opacity .2s ease;
      `;
      document.body.appendChild(t);
    }
    t.textContent = msg;
    requestAnimationFrame(() => { t.style.opacity = '1'; });
    setTimeout(() => { t.style.opacity = '0'; }, 4000);
  }

  async function markOnboardingAsSeen() {
    try {
      await fetch('/api/onboarding/marcar-visto', { method: 'POST' });
    } catch (e) { /* silencioso */ }
  }

  /* ------------ Definição dos passos por tour ------------ */
  /* Cada função retorna um array de steps para o driver.js.
     Estilo: { element: 'css selector' | null, popover: { title, description, side, align } } */

  function stepsDashboard() {
    const steps = [
      {
        popover: {
          title: 'Bem-vindo ao Sistema Financeiro 👋',
          description: 'Vamos passar pelos pontos principais. Você pode pular a qualquer momento clicando em "Sair" no canto do tooltip. Para refazer depois, use o ícone <b>?</b> no topo.',
        },
      },
      {
        element: 'main .grid, main .kpi, main [id*="kpi"], main [class*="kpi"]',
        popover: {
          title: 'Visão geral',
          description: 'Estes cards mostram os totais de acordos e mandados — total, pagos, sem pagamento, ativos e finalizados. Filtros logo abaixo refinam os números em tempo real.',
          side: 'bottom', align: 'start',
        },
      },
      {
        popover: {
          title: 'Filtros e tabs',
          description: 'Combine filtros por Status, UF e Réu pra focar num grupo específico. As tabs alternam entre Acordos e Mandados (os dois tipos de caso geridos no sistema).',
        },
      },
      {
        element: isMobile() ? null : 'aside#sidebar nav',
        popover: {
          title: 'Menu lateral',
          description: 'Acesse Acordos/Mandados ativos e finalizados, Cadastros auxiliares (admin) e Configurações pelo menu da esquerda.',
          side: 'right', align: 'start',
        },
      },
    ];
    return steps.filter(s => !s.element || $(s.element));
  }

  function stepsCadastros() {
    return [
      {
        popover: {
          title: 'Cadastros são o ponto de partida',
          description: 'Antes de criar acordos e mandados, vale conferir os <b>cadastros auxiliares</b>. Eles alimentam todos os dropdowns dos formulários: Status, UF, Réu, Local, Conta, Patrono e Prazo.',
        },
      },
      {
        element: 'select[name="table"]',
        popover: {
          title: 'Escolha o cadastro',
          description: 'Use este seletor para alternar entre as tabelas auxiliares.',
          side: 'bottom', align: 'start',
        },
      },
      {
        element: 'main table tbody tr',
        popover: {
          title: 'Cada linha é um valor utilizável',
          description: 'Os valores cadastrados aqui aparecem instantaneamente nos dropdowns dos modais de acordo/mandado.',
          side: 'bottom', align: 'start',
        },
      },
      {
        element: 'main table thead th',
        popover: {
          title: 'Cores e hierarquia',
          description: 'Em <b>Status</b>, <b>Local</b> e <b>Conta</b> você define <b>Cor</b> e <b>Hierarquia</b>. A cor pinta a linha inteira na listagem; a hierarquia define qual cor vence quando há conflito (1 = prioridade máxima).',
          side: 'bottom', align: 'start',
        },
      },
      {
        element: '[onclick*="openAddModal"], button.bg-indigo-600, button[type="button"]',
        popover: {
          title: 'Adicionar / Editar / Desativar',
          description: 'Valores em uso por acordos/mandados <b>não podem ser renomeados nem excluídos</b> — só desativados (Ativo = 0). Isso protege o histórico.',
          side: 'left', align: 'start',
        },
      },
    ].filter(s => !s.element || $(s.element));
  }

  function stepsAcordos() {
    const all = [
      {
        popover: {
          title: 'Acordos — onde tudo acontece',
          description: 'Esta é a tela principal de acordos ativos. Vamos ver os recursos mais importantes antes de criar um novo registro.',
        },
      },
      {
        element: '#acRowsCount',
        popover: {
          title: 'Contador de registros',
          description: 'Mostra quantos acordos casam com os filtros atuais. Os números nunca se limitam à página visível.',
          side: 'bottom', align: 'start',
        },
      },
      {
        element: '#acSumHonorarios',
        popover: {
          title: 'Cards de totais',
          description: 'Cada card soma <b>todos</b> os registros filtrados (não só a página). Honorários, Audiencista, Sucumbência e Correção têm cada um seu card.',
          side: 'bottom', align: 'start',
        },
      },
      {
        element: '#acSumTotalGeral',
        popover: {
          title: 'Total geral',
          description: 'Total geral = Honorários + Audiencista + Sucumbência + Correção. Útil pra fechamento contábil do período filtrado.',
          side: 'bottom', align: 'start',
        },
      },
      {
        element: 'button.ac-btn-primary',
        popover: {
          title: 'Novo acordo',
          description: 'Clique aqui para abrir o modal de cadastro. Em breve, vou explicar a regra dos cálculos automáticos no formulário.',
          side: 'left', align: 'start',
        },
      },
      {
        element: '#acTable thead th:nth-child(20)',
        popover: {
          title: 'Coluna Conferência (automática)',
          description: '<b>Conferência</b> é calculada em tempo real no navegador: <i>Correção + Honorários + Audiencista + Sucumbência + Repasse</i>. Serve pra cruzar com o valor depositado pelo banco.',
          side: 'bottom', align: 'start',
        },
      },
      {
        element: '#acTable thead th:nth-child(9) .ac-th-btn, #acTable thead th:nth-child(9)',
        popover: {
          title: 'Filtros por coluna (estilo Excel)',
          description: 'Clique no <b>▾</b> de qualquer coluna para filtrar. Múltiplas seleções são permitidas e o painel de busca interna ajuda a achar valores rápido.',
          side: 'bottom', align: 'start',
        },
      },
      {
        element: '#acTable thead th:nth-child(1) .ac-th-btn, #acTable thead th:nth-child(1)',
        popover: {
          title: 'Filtro de datas com calendário',
          description: 'Colunas de data abrem um <b>seletor de intervalo</b>: clique no dia de início, depois no de fim. O range fica em azul. Os totais recalculam pro período escolhido.',
          side: 'bottom', align: 'start',
        },
      },
      {
        element: 'button[onclick*="AC.clearAll"]',
        popover: {
          title: 'Limpar todos os filtros',
          description: 'Remove todos os filtros e ordenações de uma vez. Atalho útil quando quer voltar a ver tudo.',
          side: 'left', align: 'start',
        },
      },
      {
        element: 'tr.ac-row',
        popover: {
          title: 'Editar registro',
          description: 'Botão <b>Editar</b> ou <b>duplo clique</b> na linha abre o modal completo. O botão <b>Excluir</b> à direita remove o acordo (com confirmação).',
          side: 'top', align: 'start',
        },
      },
      // Cálculos automáticos do modal (sem âncora — explicação concentrada)
      {
        popover: {
          title: 'Cálculos automáticos do modal (parte 1/2)',
          description:
            '<b>Antes de tudo:</b> preencha <b>Tipo Réu</b> (Aéreo ou Ônibus). Ele governa o % de honorários sugerido (Aéreo = 30%, Ônibus = 40%) e libera o resto dos cálculos automáticos.<br><br>' +
            '<b>Honorários</b> = Valor Acordo × (% / 100) → preenche sozinho.<br>' +
            '<b>Repasse</b> = Valor Acordo × ((100 − %) / 100) − Audiencista → preenche sozinho.',
        },
      },
      {
        popover: {
          title: 'Cálculos automáticos do modal (parte 2/2)',
          description:
            '<b>Correção</b> = Depósito − Valor Acordo − Sucumbência → preenche sozinho assim que você lança o Depósito.<br><br>' +
            'Todos os campos marcados com badge <b>AUTO</b> podem ser sobrescritos manualmente. Se quiser voltar ao automático, basta apagar o campo e clicar fora.',
        },
      },
      {
        popover: {
          title: 'Quando vai para "Finalizados"?',
          description:
            'A regra é simples: ao escolher um <b>Status</b> que comece com <b>FINALIZADO</b> (ex.: <i>FINALIZADO COM ACORDO</i>, <i>FINALIZADO SEM ACORDO</i>), o sistema marca o registro como finalizado <b>ao salvar</b> e ele migra automaticamente para a aba <b>Acordos Finalizados</b>. Para reativar, basta abrir e trocar o status.',
        },
      },
    ];
    return all.filter(s => !s.element || $(s.element));
  }

  function stepsMandados() {
    const all = [
      {
        popover: {
          title: 'Mandados',
          description: 'A mecânica é igualzinha à de Acordos — mesmas tabelas de filtro, mesmo modal de cadastro. Mas tem algumas diferenças importantes nos totais e colunas.',
        },
      },
      {
        element: '#mdSumDeposito',
        popover: {
          title: 'Depósito e Repasse separados',
          description: 'Diferente de Acordos, em Mandados o <b>Depósito</b> e o <b>Repasse</b> aparecem como cards independentes — útil pra acompanhar o que entrou no banco vs o que foi repassado ao cliente.',
          side: 'bottom', align: 'start',
        },
      },
      {
        element: '#mdSumTotalFinal',
        popover: {
          title: 'Total Final (Mandados)',
          description: '<b>Total Final = Correção + Honorários + Audiencista + Sucumbência.</b> Atenção: <b>NÃO inclui Repasse</b> — ele já está em card próprio para evitar dupla contagem.',
          side: 'bottom', align: 'start',
        },
      },
      {
        element: '#mdTable thead th:nth-child(20)',
        popover: {
          title: 'Conferência (Mandados)',
          description: 'Mesma fórmula de Acordos: <i>Correção + Honorários + Audiencista + Sucumbência + Repasse</i>. Use junto com Sentença e Quitação para cruzar valores.',
          side: 'bottom', align: 'start',
        },
      },
      {
        element: 'button.md-btn-primary',
        popover: {
          title: 'Novo mandado',
          description: 'O modal de criação segue o mesmo fluxo do Acordo: Tipo Réu primeiro → libera Honorários/Repasse/Correção automáticos.',
          side: 'left', align: 'start',
        },
      },
      {
        popover: {
          title: 'Finalização (Mandados)',
          description: 'Mesma regra dos acordos: status que começa com <b>FINALIZADO</b> manda o registro automaticamente para a aba <b>Mandados Finalizados</b>.',
        },
      },
    ];
    return all.filter(s => !s.element || $(s.element));
  }

  function stepsFinalizados() {
    return [
      {
        popover: {
          title: 'Acordos / Mandados Finalizados',
          description:
            'Esta tela é igual à de ativos, mas mostra só os registros cujo <b>Status</b> começa com <b>FINALIZADO</b> (ex.: <i>FINALIZADO COM ACORDO</i>, <i>FINALIZADO SEM ACORDO</i>, etc.).<br><br>' +
            'A migração entre <b>Ativos ↔ Finalizados</b> é automática: basta editar o registro e mudar o status. Não existe botão "marcar como finalizado" — o sistema deriva isso do texto do status.',
        },
      },
    ];
  }

  /* ------------ Tour catálogo ------------ */

  const TOURS = {
    dashboard: { titulo: 'Dashboard', icone: '📊', steps: stepsDashboard, paginaAlvo: '/' },
    acordos:   { titulo: 'Acordos', icone: '📁', steps: stepsAcordos, paginaAlvo: '/acordos/ativos' },
    mandados:  { titulo: 'Mandados', icone: '📋', steps: stepsMandados, paginaAlvo: '/mandados/ativos' },
    cadastros: { titulo: 'Cadastros', icone: '⚙️', steps: stepsCadastros, paginaAlvo: '/cadastros', requerAdmin: true },
    finalizados: { titulo: 'Como funciona "Finalizados"', icone: '✅', steps: stepsFinalizados, paginaAlvo: null /* qualquer página de listagem */ },
  };

  /* ------------ Disparar um tour específico ------------ */

  function runTourByKey(key, onDone) {
    const def = TOURS[key];
    if (!def) { if (onDone) onDone(); return; }
    if (def.requerAdmin && !canSeeAdmin()) { if (onDone) onDone(); return; }

    const drive = getDriver();
    if (!drive) {
      console.warn('Driver.js não carregado.');
      if (onDone) onDone();
      return;
    }

    const steps = def.steps();
    if (!steps.length) {
      // Sem nenhum elemento disponível na página: pula.
      if (onDone) onDone();
      return;
    }

    const inst = drive({
      showProgress: true,
      animate: true,
      allowClose: true,
      overlayOpacity: 0.55,
      stagePadding: 6,
      stageRadius: 10,
      progressText: '{{current}} de {{total}}',
      nextBtnText: 'Próximo →',
      prevBtnText: '← Anterior',
      doneBtnText: 'Concluir',
      steps: steps,
      onDestroyed: () => { if (onDone) onDone(); },
    });
    inst.drive();
  }

  /* ------------ Welcome flow (cross-page) ------------ */

  const QUEUE_KEY = 'SF_TOUR_QUEUE';

  function buildWelcomeQueue() {
    const queue = ['dashboard', 'acordos', 'mandados'];
    if (canSeeAdmin()) queue.push('cadastros');
    return queue;
  }

  function setQueue(arr) {
    try { sessionStorage.setItem(QUEUE_KEY, JSON.stringify(arr)); }
    catch (_) {}
  }

  function getQueue() {
    try {
      const raw = sessionStorage.getItem(QUEUE_KEY);
      if (!raw) return null;
      const arr = JSON.parse(raw);
      return Array.isArray(arr) ? arr : null;
    } catch (_) { return null; }
  }

  function clearQueue() {
    try { sessionStorage.removeItem(QUEUE_KEY); } catch (_) {}
  }

  function navigateTo(path) {
    if (window.location.pathname === path) return false;
    window.location.href = path;
    return true;
  }

  function processQueue() {
    const queue = getQueue();
    if (!queue || !queue.length) return false;

    const nextKey = queue[0];
    const def = TOURS[nextKey];
    if (!def) {
      // Chave inválida, descarta e tenta próximo
      setQueue(queue.slice(1));
      return processQueue();
    }

    // Se há página alvo e não estamos nela, navega
    if (def.paginaAlvo && window.location.pathname !== def.paginaAlvo) {
      navigateTo(def.paginaAlvo);
      return true;
    }

    // Estamos na página certa: roda o tour
    // Aguarda fetch de dados terminar (acordos/mandados populam tbody async)
    const wait = (def.paginaAlvo === '/acordos/ativos' || def.paginaAlvo === '/mandados/ativos')
      ? waitFor('tbody tr.ac-row, tbody tr.md-row, tbody #acEmptyRow[style*=""], tbody #mdEmptyRow[style*=""]', 4000)
      : Promise.resolve(null);

    wait.then(() => {
      runTourByKey(nextKey, () => {
        // Tour atual concluído → shift e processa próximo
        const cur = getQueue() || [];
        setQueue(cur.slice(1));
        const remaining = getQueue();
        if (remaining && remaining.length) {
          // Há mais — navega pra próxima página
          processQueue();
        } else {
          // Acabou tudo
          clearQueue();
          markOnboardingAsSeen();
          showToast('🎉 Tour concluído! Você pode rever pelo ícone "?" no topo.');
        }
      });
    });

    return true;
  }

  function runWelcomeFlow() {
    setQueue(buildWelcomeQueue());
    processQueue();
  }

  /* ------------ Menu do botão "?" ------------ */

  function buildHelpMenu(anchorBtn) {
    // Remove menu existente
    let menu = document.getElementById('sfHelpMenu');
    if (menu) { menu.remove(); return null; }

    menu = document.createElement('div');
    menu.id = 'sfHelpMenu';
    menu.style.cssText = `
      position: fixed; min-width: 240px;
      background: #fff; border: 1px solid #e5e7eb; border-radius: 12px;
      box-shadow: 0 18px 60px rgba(0,0,0,.18); padding: 6px;
      z-index: 999998; font-size: 14px;
    `;

    const items = [
      { key: '__welcome__', label: 'Tour de boas-vindas (completo)', icon: '▶️' },
      { key: 'dashboard',   label: 'Dashboard',                       icon: '📊' },
      { key: 'acordos',     label: 'Acordos',                         icon: '📁' },
      { key: 'mandados',    label: 'Mandados',                        icon: '📋' },
      { key: 'finalizados', label: 'Como funciona "Finalizados"',     icon: '✅' },
    ];
    if (canSeeAdmin()) {
      items.splice(4, 0, { key: 'cadastros', label: 'Cadastros',     icon: '⚙️' });
    }

    items.forEach(it => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.style.cssText = `
        display: flex; align-items: center; gap: 10px;
        width: 100%; padding: 9px 12px; border: 0; background: transparent;
        text-align: left; border-radius: 8px; cursor: pointer; color: #111827;
        font-weight: 600;
      `;
      btn.innerHTML = `<span style="font-size:16px;">${it.icon}</span><span>${it.label}</span>`;
      btn.addEventListener('mouseenter', () => { btn.style.background = '#f3f4f6'; });
      btn.addEventListener('mouseleave', () => { btn.style.background = 'transparent'; });
      btn.addEventListener('click', (ev) => {
        ev.stopPropagation();
        menu.remove();
        if (it.key === '__welcome__') {
          runWelcomeFlow();
        } else {
          startTourFromMenu(it.key);
        }
      });
      menu.appendChild(btn);
    });

    // Posiciona abaixo/perto do botão
    const r = anchorBtn.getBoundingClientRect();
    menu.style.top = (r.bottom + 8) + 'px';
    menu.style.right = (window.innerWidth - r.right) + 'px';

    document.body.appendChild(menu);

    // Fecha ao clicar fora
    const closeOnOutside = (e) => {
      if (!menu.contains(e.target) && e.target !== anchorBtn) {
        menu.remove();
        document.removeEventListener('click', closeOnOutside, true);
      }
    };
    setTimeout(() => document.addEventListener('click', closeOnOutside, true), 0);

    return menu;
  }

  function startTourFromMenu(key) {
    const def = TOURS[key];
    if (!def) return;

    // Tour individual: limpa fila do welcome (caso houvesse)
    clearQueue();

    if (def.paginaAlvo && window.location.pathname !== def.paginaAlvo) {
      // Setamos uma "fila de 1 elemento" pra retomar na próxima página
      setQueue([key]);
      navigateTo(def.paginaAlvo);
      return;
    }

    // Estamos na página certa OU o tour não exige página
    const isList = (def.paginaAlvo === '/acordos/ativos' || def.paginaAlvo === '/mandados/ativos');
    const wait = isList
      ? waitFor('tbody tr.ac-row, tbody tr.md-row', 3000)
      : Promise.resolve(null);
    wait.then(() => runTourByKey(key, () => {
      // Tour individual → não persiste "visto" automaticamente
    }));
  }

  /* ------------ Boot ------------ */

  function bindHelpButton() {
    const btn = document.getElementById('onboardingHelpBtn');
    if (!btn || btn.dataset.sfBound === '1') return;
    btn.dataset.sfBound = '1';
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      buildHelpMenu(btn);
    });
  }

  function init() {
    const ctx = global.SF_ONBOARDING || {};
    if (!ctx.autenticado) return;

    bindHelpButton();

    // 1) Há uma fila em andamento (vindo de navegação cross-page)?
    const queue = getQueue();
    if (queue && queue.length) {
      // Aguarda 300ms pro DOM estabilizar antes de continuar a fila
      setTimeout(() => processQueue(), 300);
      return;
    }

    // 2) Primeiro login? Dispara fluxo completo.
    if (!ctx.visto) {
      // Garante que a página atual seja a alvo do primeiro tour da fila
      if (window.location.pathname !== '/') {
        setQueue(buildWelcomeQueue());
        navigateTo('/');
        return;
      }
      setTimeout(() => runWelcomeFlow(), 800);
    }
  }

  global.SistemaTour = { init, runTour: runTourByKey, runWelcomeFlow };
})(window);
