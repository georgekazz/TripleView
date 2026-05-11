/* ═══════════════════════════════════════════════════════════════
   VISUAL QUERY BUILDER  —  vqb.js
   Production-grade visual SPARQL editor for UCO / MITRE / STIX
   ═══════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  // ── ONTOLOGY SCHEMA ──────────────────────────────────────────
  const NS = {
    'uco-action':   'https://ontology.unifiedcyberontology.org/uco/action/',
    'uco-core':     'https://ontology.unifiedcyberontology.org/uco/core/',
    'uco-tool':     'https://ontology.unifiedcyberontology.org/uco/tool/',
    'uco-identity': 'https://ontology.unifiedcyberontology.org/uco/identity/',
    'uco-marking':  'https://ontology.unifiedcyberontology.org/uco/marking/',
    'uco-analysis': 'https://ontology.unifiedcyberontology.org/uco/analysis/',
    'stix-uco':     'http://example.org/stix-uco/',
    'rdf':          'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
    'xsd':          'http://www.w3.org/2001/XMLSchema#',
  };

  const GRAPH = {
    mitre: 'http://example.org/graph/mitre',
    stix:  'http://stix/',
    ncsc:  'http://ncsc/',
    all:   null,   // no FROM = all graphs
  };

  // ── NODE TYPES ───────────────────────────────────────────────
  const TYPES = [
    { id:'Technique',   label:'ATT&CK Technique',   uri:'uco-action:ActionPattern',       color:'#5b8af5', graph:'mitre', var:'technique',    name:'uco-core:name',               desc:'MITRE ATT&CK technique or sub-technique',  icon:'⚔️' },
    { id:'Malware',     label:'Malware / Tool',      uri:'uco-tool:MaliciousTool',         color:'#f07070', graph:'stix',  var:'malware',       name:'uco-core:name',               desc:'Malware or malicious software',            icon:'🦠' },
    { id:'Mitigation',  label:'Defensive Tool',      uri:'uco-tool:DefensiveTool',         color:'#4ec9a0', graph:'stix',  var:'mitigation',    name:'uco-core:name',               desc:'Security or defensive tool / mitigation',  icon:'🛡️' },
    { id:'Tool',        label:'Generic Tool',        uri:'uco-tool:Tool',                  color:'#f0c060', graph:'stix',  var:'tool',          name:'uco-core:name',               desc:'Generic software tool',                    icon:'🔧' },
    { id:'Group',       label:'Threat Group / Org',  uri:'uco-identity:Organization',      color:'#56d9e8', graph:'stix',  var:'group',         name:'uco-core:name',               desc:'Threat actor group or organization',       icon:'👥' },
    { id:'Campaign',    label:'Campaign / Bundle',   uri:'uco-core:Grouping',              color:'#b48ef5', graph:'stix',  var:'campaign',      name:'uco-core:name',               desc:'Campaign, bundle or grouping of objects',  icon:'🎯' },
    { id:'DataSource',  label:'Data Source',         uri:'stix-uco:DataSource',            color:'#4ec9a0', graph:'stix',  var:'dataSource',    name:'uco-core:name',               desc:'A data source used for detection',         icon:'📡' },
    { id:'DataComp',    label:'Data Component',      uri:'stix-uco:DataComponent',         color:'#56d9e8', graph:'stix',  var:'dataComponent', name:'uco-core:name',               desc:'A component within a data source',         icon:'🔍' },
    { id:'ExtRef',      label:'External Reference',  uri:'uco-core:ExternalReference',     color:'#8890a8', graph:'mitre', var:'ref',           name:'uco-core:externalIdentifier', desc:'CVE, CAPEC, or ATT&CK T-code reference',   icon:'🔗' },
    { id:'Relationship',label:'Relationship',        uri:'uco-core:Relationship',          color:'#f0c060', graph:'mitre', var:'rel',           name:'uco-core:kindOfRelationship', desc:'A directional relationship between nodes',  icon:'↔️' },
    { id:'AnalyticResult',label:'Analytic Result',   uri:'uco-analysis:AnalyticResult',    color:'#c792ea', graph:'stix',  var:'analytic',      name:'uco-core:name',               desc:'Result of a detection or analytics action', icon:'📊' },
  ];

  // ── RELATION DEFINITIONS ─────────────────────────────────────
  // via:'Relationship'  → triple goes through an explicit uco-core:Relationship node
  // via:null            → direct predicate between subject and object
  const RELS = [
    // ── Through Relationship node (uco-core:kindOfRelationship) ──
    { id:'uses',          label:'uses',           kind:'uses',             via:'Relationship', pred:'uco-core:kindOfRelationship',
      from:['Malware','Tool','Group','Campaign'],  to:['Technique','Malware','Tool'],
      color:'#f07070', desc:'Malware/actor uses a technique or tool' },

    { id:'mitigates',     label:'mitigates',      kind:'mitigates',        via:'Relationship', pred:'uco-core:kindOfRelationship',
      from:['Mitigation'],                         to:['Technique'],
      color:'#4ec9a0', desc:'Mitigation counters a technique' },

    { id:'detects',       label:'detects',        kind:'detects',          via:'Relationship', pred:'uco-core:kindOfRelationship',
      from:['DataSource','DataComp'],              to:['Technique'],
      color:'#56d9e8', desc:'Data source detects a technique' },

    { id:'subtechOf',     label:'subtechnique-of',kind:'subtechnique-of',  via:'Relationship', pred:'uco-core:kindOfRelationship',
      from:['Technique'],                          to:['Technique'],
      color:'#5b8af5', desc:'Sub-technique of a parent technique' },

    { id:'revokedBy',     label:'revoked-by',     kind:'revoked-by',       via:'Relationship', pred:'uco-core:kindOfRelationship',
      from:['Technique','Malware','Mitigation'],   to:['Technique','Malware','Mitigation'],
      color:'#8890a8', desc:'This object was revoked and replaced' },

    { id:'attributedTo',  label:'attributed-to',  kind:'attributed-to',    via:'Relationship', pred:'uco-core:kindOfRelationship',
      from:['Campaign'],                           to:['Group'],
      color:'#b48ef5', desc:'Campaign attributed to a threat group' },

    { id:'targets',       label:'targets',        kind:'targets',          via:'Relationship', pred:'uco-core:kindOfRelationship',
      from:['Group','Malware'],                    to:['Group'],
      color:'#f0c060', desc:'Actor or malware targets an organization' },

    // ── Direct predicates ──
    { id:'hasName',       label:'has name',       kind:null,               via:null, pred:'uco-core:name',
      from:['Technique','Malware','Mitigation','Tool','Group','Campaign','DataSource','DataComp','AnalyticResult'],
      to:['__literal__'],
      color:'#8890a8', desc:'Filter or retrieve the entity name' },

    { id:'hasAttackId',   label:'has ATT&CK ID',  kind:null,               via:null, pred:'uco-core:externalIdentifier',
      from:['ExtRef'],                             to:['__literal__'],
      color:'#5b8af5', desc:'The T-code or CAPEC/CVE identifier' },

    { id:'hasExtRef',     label:'has reference',  kind:null,               via:null, pred:'uco-core:externalReference',
      from:['Technique','Malware','Tool','Mitigation'], to:['ExtRef'],
      color:'#8890a8', desc:'Link to an external reference node' },

    { id:'hasRefUrl',     label:'has URL',         kind:null,              via:null, pred:'uco-core:referenceURL',
      from:['ExtRef'],                             to:['__literal__'],
      color:'#56d9e8', desc:'URL of the external reference' },

    { id:'hasCreated',    label:'created time',    kind:null,              via:null, pred:'uco-core:objectCreatedTime',
      from:['Technique','Malware','Mitigation','Tool','Group','Campaign','Relationship'],
      to:['__literal__'],
      color:'#8890a8', desc:'When the object was created (datetime)' },

    { id:'hasModified',   label:'modified time',   kind:null,              via:null, pred:'uco-core:modifiedTime',
      from:['Technique','Malware','Mitigation','Tool','Group','Campaign','Relationship'],
      to:['__literal__'],
      color:'#8890a8', desc:'When the object was last modified (datetime)' },

    { id:'hasSpecVer',    label:'spec version',    kind:null,              via:null, pred:'uco-core:specVersion',
      from:['Technique','Malware','Mitigation','Tool','Group','Campaign'],
      to:['__literal__'],
      color:'#8890a8', desc:'STIX/UCO specification version' },

    { id:'hasDescription',label:'has description', kind:null,              via:null, pred:'uco-core:description',
      from:['Technique','Malware','Mitigation','Tool','Group','Campaign','Relationship'],
      to:['__literal__'],
      color:'#8890a8', desc:'Free-text description of the entity' },

    { id:'hasRelKind',    label:'relationship type',kind:null,             via:null, pred:'uco-core:kindOfRelationship',
      from:['Relationship'],                       to:['__literal__'],
      color:'#f0c060', desc:'The kind/type of this relationship' },

    { id:'hasSource',     label:'has source',       kind:null,             via:null, pred:'uco-core:source',
      from:['Relationship'],                       to:['Technique','Malware','Mitigation','Tool','Group','Campaign','DataSource'],
      color:'#5b8af5', desc:'Source entity of the relationship' },

    { id:'hasTarget',     label:'has target',       kind:null,             via:null, pred:'uco-core:target',
      from:['Relationship'],                       to:['Technique','Malware','Mitigation','Tool','Group','Campaign'],
      color:'#f07070', desc:'Target entity of the relationship' },

    { id:'hasObject',     label:'contains object',  kind:null,             via:null, pred:'uco-core:object',
      from:['Campaign'],                           to:['Technique','Malware','Mitigation','Tool','Relationship'],
      color:'#b48ef5', desc:'Object contained within a bundle/campaign' },

    { id:'isSubtech',     label:'is sub-technique', kind:null,             via:null, pred:'stix-uco:attackOntologyClass',
      from:['Technique'],                          to:['__literal__'],
      color:'#5b8af5', desc:'Ontology class (Technique / Sub-technique)' },

    { id:'anyPred',       label:'any predicate',    kind:null,             via:null, pred:null,
      from:['*'],                                  to:['*'],
      color:'#50566a', desc:'Any RDF predicate — freestyle triple pattern' },
  ];

  // Filter operators for literal values
  const FILTER_OPS = [
    { id:'contains',  label:'contains',       sparql: (v,val) => `CONTAINS(LCASE(STR(${v})), "${val.toLowerCase()}")` },
    { id:'equals',    label:'equals',         sparql: (v,val) => `STR(${v}) = "${val}"` },
    { id:'startswith',label:'starts with',    sparql: (v,val) => `STRSTARTS(LCASE(STR(${v})), "${val.toLowerCase()}")` },
    { id:'endswith',  label:'ends with',      sparql: (v,val) => `STRENDS(LCASE(STR(${v})), "${val.toLowerCase()}")` },
    { id:'regex',     label:'regex',          sparql: (v,val) => `REGEX(STR(${v}), "${val}", "i")` },
    { id:'gt',        label:'>',              sparql: (v,val) => `${v} > "${val}"^^xsd:dateTime` },
    { id:'lt',        label:'<',              sparql: (v,val) => `${v} < "${val}"^^xsd:dateTime` },
    { id:'not',       label:'not contains',   sparql: (v,val) => `!CONTAINS(LCASE(STR(${v})), "${val.toLowerCase()}")` },
  ];

  // ── STATE ────────────────────────────────────────────────────
  let conditions = [];   // array of condition objects
  let condSeq    = 0;    // id counter
  let varMap     = {};   // varPrefix → count (for unique var names)

  function freshVar(prefix) {
    varMap[prefix] = (varMap[prefix] || 0) + 1;
    return varMap[prefix] === 1 ? `?${prefix}` : `?${prefix}${varMap[prefix]}`;
  }
  function resetVars() { varMap = {}; }
  function vn(v) { return v.replace('?',''); }   // strip ?

  // ── DOM REFS ─────────────────────────────────────────────────
  const DOM = {
    body:     () => document.getElementById('vqb-body'),
    preview:  () => document.getElementById('vqb-sparql-preview'),
    code:     () => document.getElementById('vqb-sparql-code'),
    send:     () => document.getElementById('vqb-sparql-send'),
    copy:     () => document.getElementById('vqb-sparql-copy'),
    generate: () => document.getElementById('vqb-btn-generate'),
    clear:    () => document.getElementById('vqb-btn-clear'),
    limit:    () => document.getElementById('vqb-limit'),
    distinct: () => document.getElementById('vqb-distinct'),
    orderVar: () => document.getElementById('vqb-order-var'),
    orderDir: () => document.getElementById('vqb-order-dir'),
  };

  // ── RENDER ───────────────────────────────────────────────────
  function render() {
    const body = DOM.body();
    body.innerHTML = '';
    resetVars();

    if (conditions.length === 0) {
      body.innerHTML = `
        <div class="vqb-empty">
          <div class="vqb-empty-icon">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                 stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/>
              <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
              <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
            </svg>
          </div>
          <div class="vqb-empty-title">Build your query visually</div>
          <div class="vqb-empty-desc">
            Click <strong>＋ Add condition</strong> to start. Pick a subject type, a relationship, and an
            object — SPARQL is generated live. Chain multiple conditions, add filters, and ORDER BY.
          </div>
        </div>`;
      DOM.preview().classList.remove('visible');
      return;
    }

    conditions.forEach((cond, idx) => {
      // AND / UNION connector between rows
      if (idx > 0) {
        const conn = document.createElement('div');
        conn.className = 'vqb-connector';
        const lbl = document.createElement('span');
        lbl.className = 'vqb-connector-label';
        const sel = document.createElement('select');
        sel.className = 'vqb-connector-select';
        sel.title = 'How to combine with previous condition';
        [['and','AND'],['union','UNION'],['optional','OPTIONAL'],['minus','MINUS']].forEach(([v,l]) => {
          const o = document.createElement('option');
          o.value = v; o.textContent = l;
          if (v === (cond.combinator || 'and')) o.selected = true;
          sel.appendChild(o);
        });
        sel.addEventListener('change', () => { cond.combinator = sel.value; generateSPARQL(); });
        conn.appendChild(sel);
        body.appendChild(conn);
      }

      // Row wrapper
      const rowWrap = document.createElement('div');
      rowWrap.style.display = 'flex';
      rowWrap.style.flexDirection = 'column';
      rowWrap.style.gap = '4px';

      // Main row
      const row = document.createElement('div');
      row.className = 'vqb-row';

      // Row number
      const num = document.createElement('div');
      num.className = 'vqb-row-num';
      num.textContent = idx + 1;
      row.appendChild(num);

      // Subject pill
      row.appendChild(makeTypePill(cond, 'subject'));

      // Arrow
      row.appendChild(makeArrow());

      // Relation pill
      row.appendChild(makeRelPill(cond));

      // Arrow
      row.appendChild(makeArrow());

      // Object pill
      row.appendChild(makeTypePill(cond, 'object'));

      // Optional toggle
      const optBtn = document.createElement('button');
      optBtn.className = 'vqb-opt-btn' + (cond.optional ? ' active-green' : '');
      optBtn.title = 'Make this condition OPTIONAL';
      optBtn.innerHTML = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg> OPT`;
      optBtn.addEventListener('click', () => { cond.optional = !cond.optional; render(); });
      row.appendChild(optBtn);

      // Delete button
      const del = document.createElement('button');
      del.className = 'vqb-btn-del';
      del.title = 'Remove condition';
      del.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`;
      del.addEventListener('click', () => { conditions = conditions.filter(c => c.id !== cond.id); render(); });
      row.appendChild(del);

      rowWrap.appendChild(row);

      // Options strip (filter + order by) — shown when condition has subject+relation+object
      if (cond.subjectType && cond.relation && cond.objectType) {
        rowWrap.appendChild(makeOptsStrip(cond));
      }

      body.appendChild(rowWrap);
    });

    // Add condition button
    const addWrap = document.createElement('div');
    addWrap.className = 'vqb-add-row';
    const addBtn = document.createElement('button');
    addBtn.className = 'vqb-btn-add';
    addBtn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg> Add condition`;
    addBtn.addEventListener('click', addCondition);
    addWrap.appendChild(addBtn);
    body.appendChild(addWrap);

    generateSPARQL();
  }

  // ── TYPE PILL ────────────────────────────────────────────────
  function makeTypePill(cond, side) {
    const wrap = document.createElement('div');
    wrap.className = 'vqb-node';

    const typeId = side === 'subject' ? cond.subjectType : cond.objectType;
    const varVal = side === 'subject' ? cond.subjectVar  : cond.objectVar;
    const type   = TYPES.find(t => t.id === typeId);
    const isLit  = typeId === '__literal__';

    const pill = document.createElement('div');
    pill.className = 'vqb-pill' + (typeId ? ' has-value' : '');
    if (type) pill.style.borderColor = type.color + '88';

    pill.innerHTML = `
      <span class="vqb-pill-dot" style="background:${type ? type.color : '#50566a'}"></span>
      <span class="vqb-pill-label">${type ? type.label : isLit ? 'Literal' : `${side === 'subject' ? 'Subject' : 'Object'}…`}</span>
      ${varVal ? `<span class="vqb-pill-var">${varVal}</span>` : ''}
      <svg class="vqb-pill-chevron" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>`;

    wrap.appendChild(pill);
    buildTypeDropdown(cond, side, pill);
    return wrap;
  }

  function buildTypeDropdown(cond, side, trigger) {
    const { dd, sinput, list, info } = makeDropdownShell();
    sinput.placeholder = 'Search types…';

    function populate(filter) {
      list.innerHTML = '';
      let types = TYPES;

      // If object side, filter to what the relation allows
      if (side === 'object' && cond.relation) {
        const rel = RELS.find(r => r.id === cond.relation);
        if (rel && !rel.to.includes('*')) {
          const allowed = rel.to;
          types = TYPES.filter(t => allowed.includes(t.id));
          if (allowed.includes('__literal__')) {
            types = [...types, {
              id:'__literal__', label:'Literal value', color:'#8890a8',
              var:'val', graph:null, desc:'A text, number, or date value to filter or display', icon:'📝'
            }];
          }
        }
      }

      if (filter) types = types.filter(t => t.label.toLowerCase().includes(filter.toLowerCase()) || (t.desc||'').toLowerCase().includes(filter.toLowerCase()));
      if (!types.length) { list.innerHTML = '<div class="vqb-dd-empty">No types found</div>'; return; }

      types.forEach(t => {
        const item = document.createElement('div');
        item.className = 'vqb-dd-item' + (((side==='subject'?cond.subjectType:cond.objectType)===t.id)?' active':'');
        item.innerHTML = `<span class="vqb-dd-dot" style="background:${t.color||'#8890a8'}"></span>
          <span class="vqb-dd-item-label">${t.label}</span>`;
        item.addEventListener('mouseenter', () => {
          list.querySelectorAll('.vqb-dd-item').forEach(i=>i.classList.remove('active'));
          item.classList.add('active');
          info.innerHTML = `
            <div class="vqb-dd-info-dot" style="background:${t.color||'#8890a8'}"></div>
            <div class="vqb-dd-info-name">${t.label}</div>
            <div class="vqb-dd-info-desc">${t.desc||''}</div>
            ${t.graph ? `<div class="vqb-dd-info-graph">Graph: ${t.graph}</div>` : ''}`;
        });
        item.addEventListener('click', () => {
          if (side === 'subject') {
            const prev = cond.subjectType;
            cond.subjectType = t.id;
            cond.subjectVar  = freshVar(t.var || 'subject');
            // Reset downstream if type changed
            if (prev !== t.id) { cond.relation = null; cond.objectType = null; cond.objectVar = null; cond.filterValue = ''; }
          } else {
            cond.objectType = t.id;
            cond.objectVar  = (t.id === '__literal__') ? null : freshVar(t.var || 'object');
          }
          closeDropdowns();
          render();
        });
        list.appendChild(item);
      });

      // Auto-preview first
      const first = list.querySelector('.vqb-dd-item.active') || list.querySelector('.vqb-dd-item');
      if (first) first.dispatchEvent(new MouseEvent('mouseenter'));
    }

    sinput.addEventListener('input', () => populate(sinput.value));

    trigger.addEventListener('click', e => {
      e.stopPropagation();
      const wasOpen = dd.classList.contains('open');
      closeDropdowns();
      if (!wasOpen) {
        document.body.appendChild(dd);
        positionDD(dd, trigger);
        dd.classList.add('open');
        trigger.classList.add('open');
        sinput.value = '';
        populate('');
        sinput.focus();
      }
    });
  }

  // ── RELATION PILL ────────────────────────────────────────────
  function makeRelPill(cond) {
    const wrap = document.createElement('div');
    wrap.className = 'vqb-node';

    const rel = RELS.find(r => r.id === cond.relation);

    const pill = document.createElement('div');
    pill.className = 'vqb-pill vqb-rel-pill' + (rel ? ' has-value' : '');
    if (rel) pill.style.borderColor = rel.color + '99';

    pill.innerHTML = `
      <span class="vqb-pill-dot" style="background:${rel ? rel.color : 'var(--amber)'}"></span>
      <span class="vqb-pill-label">${rel ? rel.label : 'Relation…'}</span>
      <svg class="vqb-pill-chevron" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>`;

    wrap.appendChild(pill);
    buildRelDropdown(cond, pill);
    return wrap;
  }

  function buildRelDropdown(cond, trigger) {
    const { dd, sinput, list, info } = makeDropdownShell();
    sinput.placeholder = 'Search relations…';

    function populate(filter) {
      list.innerHTML = '';
      let rels = RELS;

      // Only show relations compatible with selected subject type
      if (cond.subjectType) {
        rels = rels.filter(r => r.from.includes('*') || r.from.includes(cond.subjectType));
      }
      if (filter) rels = rels.filter(r => r.label.toLowerCase().includes(filter.toLowerCase()) || r.desc.toLowerCase().includes(filter.toLowerCase()));
      if (!rels.length) { list.innerHTML = '<div class="vqb-dd-empty">No relations available</div>'; return; }

      // Group by via type
      const groups = { 'Via Relationship node': rels.filter(r=>r.via==='Relationship'), 'Direct predicate': rels.filter(r=>!r.via && r.pred), 'Freestyle': rels.filter(r=>!r.via && !r.pred) };

      Object.entries(groups).forEach(([grpLabel, grpRels]) => {
        if (!grpRels.length) return;
        const grp = document.createElement('div');
        grp.style.cssText = 'padding:8px 12px 3px;font-size:10px;font-weight:700;letter-spacing:.09em;text-transform:uppercase;color:var(--text-muted)';
        grp.textContent = grpLabel;
        list.appendChild(grp);

        grpRels.forEach(r => {
          const item = document.createElement('div');
          item.className = 'vqb-dd-item' + (cond.relation===r.id?' active':'');
          item.innerHTML = `<span class="vqb-dd-dot" style="background:${r.color}"></span>
            <span class="vqb-dd-item-label">${r.label}</span>
            <span class="vqb-dd-item-sub">${r.via?'→ Rel':'direct'}</span>`;
          item.addEventListener('mouseenter', () => {
            list.querySelectorAll('.vqb-dd-item').forEach(i=>i.classList.remove('active'));
            item.classList.add('active');
            info.innerHTML = `
              <div class="vqb-dd-info-dot" style="background:${r.color}"></div>
              <div class="vqb-dd-info-name">${r.label}</div>
              <div class="vqb-dd-info-desc">${r.desc}</div>
              <div class="vqb-dd-info-graph">${r.via ? 'via uco-core:Relationship' : r.pred ? r.pred : 'any predicate'}</div>`;
          });
          item.addEventListener('click', () => {
            const prev = cond.relation;
            cond.relation = r.id;
            if (prev !== r.id) { cond.objectType = null; cond.objectVar = null; cond.filterValue = ''; }
            closeDropdowns();
            render();
          });
          list.appendChild(item);
        });
      });

      const first = list.querySelector('.vqb-dd-item.active') || list.querySelector('.vqb-dd-item');
      if (first) first.dispatchEvent(new MouseEvent('mouseenter'));
    }

    sinput.addEventListener('input', () => populate(sinput.value));

    trigger.addEventListener('click', e => {
      e.stopPropagation();
      const wasOpen = dd.classList.contains('open');
      closeDropdowns();
      if (!wasOpen) {
        document.body.appendChild(dd);
        positionDD(dd, trigger);
        dd.classList.add('open');
        trigger.classList.add('open');
        sinput.value = '';
        populate('');
        sinput.focus();
      }
    });
  }

  function makeOptsStrip(cond) {
    const strip = document.createElement('div');
    strip.className = 'vqb-row-opts';

    // Filter button + inline filter input
    const filterBtn = document.createElement('button');
    filterBtn.className = 'vqb-opt-btn' + (cond.filterValue ? ' active' : '');
    filterBtn.innerHTML = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg> Filter`;
    filterBtn.title = 'Add a FILTER condition';

    const filterWrap = document.createElement('div');
    filterWrap.className = 'vqb-inline-filter';
    filterWrap.style.display = cond.filterValue !== undefined && cond.showFilter ? 'flex' : 'none';

    const opSel = document.createElement('select');
    opSel.className = 'vqb-filter-op';
    FILTER_OPS.forEach(op => {
      const o = document.createElement('option');
      o.value = op.id; o.textContent = op.label;
      if (op.id === (cond.filterOp || 'contains')) o.selected = true;
      opSel.appendChild(o);
    });
    opSel.addEventListener('change', () => { cond.filterOp = opSel.value; generateSPARQL(); });

    const filterInput = document.createElement('input');
    filterInput.placeholder = 'Filter value…';
    filterInput.value = cond.filterValue || '';
    filterInput.addEventListener('input', () => { cond.filterValue = filterInput.value; generateSPARQL(); });

    filterWrap.appendChild(document.createTextNode(''));
    filterWrap.insertBefore((() => {
      const ico = document.createElement('span');
      ico.innerHTML = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>`;
      return ico;
    })(), null);
    filterWrap.appendChild(opSel);
    filterWrap.appendChild(filterInput);

    filterBtn.addEventListener('click', () => {
      cond.showFilter = !cond.showFilter;
      filterWrap.style.display = cond.showFilter ? 'flex' : 'none';
      filterBtn.classList.toggle('active', cond.showFilter);
      if (cond.showFilter) filterInput.focus();
      else { cond.filterValue = ''; filterInput.value = ''; generateSPARQL(); }
    });
    if (cond.showFilter) filterBtn.classList.add('active');

    strip.appendChild(filterBtn);
    strip.appendChild(filterWrap);

    const orderBtn = document.createElement('button');
    orderBtn.className = 'vqb-opt-btn' + (cond.orderBy ? ' active-amber' : '');
    orderBtn.innerHTML = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg> Order`;
    orderBtn.title = 'Add ORDER BY for this variable';

    const orderDir = document.createElement('select');
    orderDir.className = 'vqb-order-select';
    orderDir.style.display = cond.orderBy ? 'flex' : 'none';
    [['asc','ASC ↑'],['desc','DESC ↓']].forEach(([v,l]) => {
      const o = document.createElement('option');
      o.value = v; o.textContent = l;
      if (v === (cond.orderDir || 'asc')) o.selected = true;
      orderDir.appendChild(o);
    });
    orderDir.addEventListener('change', () => { cond.orderDir = orderDir.value; generateSPARQL(); });

    orderBtn.addEventListener('click', () => {
      cond.orderBy = !cond.orderBy;
      orderBtn.classList.toggle('active-amber', cond.orderBy);
      orderDir.style.display = cond.orderBy ? 'inline-block' : 'none';
      generateSPARQL();
    });

    strip.appendChild(orderBtn);
    strip.appendChild(orderDir);

    // NOT EXISTS toggle
    const notBtn = document.createElement('button');
    notBtn.className = 'vqb-opt-btn' + (cond.notExists ? ' active' : '');
    notBtn.innerHTML = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg> NOT EXISTS`;
    notBtn.title = 'Wrap this condition in FILTER NOT EXISTS';
    notBtn.addEventListener('click', () => { cond.notExists = !cond.notExists; notBtn.classList.toggle('active', cond.notExists); generateSPARQL(); });
    strip.appendChild(notBtn);

    return strip;
  }

  function generateSPARQL() {
    const valid = conditions.filter(c => c.subjectType && c.relation && c.objectType);
    if (!valid.length) { DOM.preview().classList.remove('visible'); return; }

    const usedPfx   = new Set(['uco-core']);
    const graphs    = new Set();
    const selectSet = new Set();
    const orderParts= [];
    const blocks    = [];

    valid.forEach((cond, idx) => {
      const subT = TYPES.find(t => t.id === cond.subjectType);
      const objT = (cond.objectType !== '__literal__') ? TYPES.find(t => t.id === cond.objectType) : null;
      const rel  = RELS.find(r => r.id === cond.relation);
      if (!subT || !rel) return;

      [subT.uri, objT?.uri, rel.pred].filter(Boolean).forEach(u => {
        const pfx = u.split(':')[0];
        if (NS[pfx]) usedPfx.add(pfx);
      });

      if (subT.graph) graphs.add(GRAPH[subT.graph]);
      if (objT?.graph) graphs.add(GRAPH[objT.graph]);

      if (!cond.subjectVar) cond.subjectVar = freshVar(subT.var);
      const sVar = cond.subjectVar;
      const oVar = (cond.objectType !== '__literal__' && !cond.objectVar)
        ? (cond.objectVar = freshVar(objT?.var || 'obj'))
        : cond.objectVar;

      selectSet.add(sVar);
      if (oVar) selectSet.add(oVar);

      const lines = [];

      if (rel.via === 'Relationship') {

        const relVar = `?relNode${idx}`;
        selectSet.add(relVar);
        usedPfx.add('uco-core');
        lines.push(`  ${sVar} a ${subT.uri} .`);
        lines.push(`  ${relVar} a uco-core:Relationship ;`);
        lines.push(`         uco-core:kindOfRelationship "${rel.kind}" ;`);
        lines.push(`         uco-core:source ${sVar} ;`);
        if (oVar && cond.objectType !== '__literal__') {
          lines.push(`         uco-core:target ${oVar} .`);
          if (objT) lines.push(`  ${oVar} a ${objT.uri} .`);
        } else {
          lines[lines.length-1] = lines[lines.length-1].replace(' ;', ' .');
        }

        const sNameVar = `?${vn(sVar)}Name`;
        lines.push(`  OPTIONAL { ${sVar} uco-core:name ${sNameVar} . FILTER (!CONTAINS(COALESCE(STR(${sNameVar}),""), "@")) FILTER (!CONTAINS(COALESCE(STR(${sNameVar}),""), " - ")) }`);
        selectSet.add(sNameVar);
        if (oVar && objT) {
          const oNameVar = `?${vn(oVar)}Name`;
          lines.push(`  OPTIONAL { ${oVar} uco-core:name ${oNameVar} . FILTER (!CONTAINS(COALESCE(STR(${oNameVar}),""), "@")) FILTER (!CONTAINS(COALESCE(STR(${oNameVar}),""), " - ")) }`);
          selectSet.add(oNameVar);
        }

        if (cond.filterValue) {
          const op = FILTER_OPS.find(o => o.id === (cond.filterOp || 'contains'));
          if (op) lines.push(`  FILTER (${op.sparql(sNameVar, cond.filterValue)})`);
        }

      } else if (rel.pred) {

        lines.push(`  ${sVar} a ${subT.uri} .`);

        if (cond.objectType === '__literal__') {
          const litVar = `?${vn(sVar)}_${vn(rel.pred.split(':')[1]||'val')}`;
          lines.push(`  ${sVar} ${rel.pred} ${litVar} .`);
          selectSet.add(litVar);
          if (cond.filterValue) {
            const op = FILTER_OPS.find(o => o.id === (cond.filterOp || 'contains'));
            if (op) lines.push(`  FILTER (${op.sparql(litVar, cond.filterValue)})`);
          }
        } else {
          lines.push(`  ${sVar} ${rel.pred} ${oVar} .`);
          if (objT) lines.push(`  ${oVar} a ${objT.uri} .`);
          // Optional name for object
          if (objT?.name) {
            const oNameVar = `?${vn(oVar)}Name`;
            lines.push(`  OPTIONAL { ${oVar} ${objT.name} ${oNameVar} }`);
            selectSet.add(oNameVar);
          }
        }

      } else {
        const predVar = `?pred${idx}`;
        lines.push(`  ${sVar} a ${subT.uri} .`);
        if (oVar && objT) {
          lines.push(`  ${sVar} ${predVar} ${oVar} .`);
          lines.push(`  ${oVar} a ${objT.uri} .`);
          selectSet.add(predVar);
        }
      }

      if (cond.orderBy) {
        const orderVar = selectSet.size > 0 ? [...selectSet][0] : sVar;
        orderParts.push(`${(cond.orderDir||'asc').toUpperCase()}(${orderVar})`);
      }

      blocks.push({ lines, optional: cond.optional, combinator: cond.combinator || 'and', notExists: cond.notExists });
    });

    const pfxLines = [...usedPfx].map(p => `PREFIX ${p}: <${NS[p]}>`);
    if ([...selectSet].some(v => v.includes('dateTime'))) usedPfx.add('xsd');

    const fromLines = [...graphs].filter(Boolean).map(g => `FROM <${g}>`);

    const whereLines = [];
    blocks.forEach((b, i) => {
      if (i === 0) {
        if (b.notExists) {
          whereLines.push('  FILTER NOT EXISTS {');
          b.lines.forEach(l => whereLines.push('  ' + l));
          whereLines.push('  }');
        } else if (b.optional) {
          whereLines.push('  OPTIONAL {');
          b.lines.forEach(l => whereLines.push('  ' + l));
          whereLines.push('  }');
        } else {
          b.lines.forEach(l => whereLines.push(l));
        }
      } else {
        const combinator = b.combinator || 'and';
        if (combinator === 'union') {
          whereLines.push('  UNION {');
          b.lines.forEach(l => whereLines.push('  ' + l));
          whereLines.push('  }');
        } else if (combinator === 'optional') {
          whereLines.push('  OPTIONAL {');
          b.lines.forEach(l => whereLines.push('  ' + l));
          whereLines.push('  }');
        } else if (combinator === 'minus') {
          whereLines.push('  MINUS {');
          b.lines.forEach(l => whereLines.push('  ' + l));
          whereLines.push('  }');
        } else if (b.notExists) {
          whereLines.push('  FILTER NOT EXISTS {');
          b.lines.forEach(l => whereLines.push('  ' + l));
          whereLines.push('  }');
        } else {
          b.lines.forEach(l => whereLines.push(l));
        }
      }
    });

    const distinct = DOM.distinct().checked ? 'DISTINCT ' : '';
    const limit    = DOM.limit().value;
    const selectVarStr = [...selectSet].join(' ');
    const orderLine = orderParts.length ? `ORDER BY ${orderParts.join(' ')}` : null;

    const sparqlParts = [
      ...pfxLines,
      '',
      `SELECT ${distinct}${selectVarStr}`,
      ...fromLines,
      'WHERE {',
      ...whereLines,
      '}',
      ...(orderLine ? [orderLine] : []),
      `LIMIT ${limit}`,
    ].filter((l,i,arr) => !(l==='' && (i===0 || arr[i-1]==='')));

    const sparqlRaw = sparqlParts.join('\n');
    DOM.code().innerHTML = syntaxHighlight(sparqlRaw);
    DOM.preview().classList.add('visible');
  }

  function syntaxHighlight(sparql) {
    const kws = ['SELECT','DISTINCT','WHERE','FILTER','OPTIONAL','UNION','LIMIT','OFFSET',
      'ORDER BY','GROUP BY','HAVING','PREFIX','BASE','GRAPH','SERVICE','BIND','VALUES',
      'MINUS','REDUCED','FROM','NAMED','CONSTRUCT','ASK','DESCRIBE','AS','COUNT','SUM',
      'AVG','MIN','MAX','STRSTARTS','CONTAINS','LCASE','UCASE','LANG','STR','CONCAT',
      'COALESCE','IF','BOUND','NOT EXISTS','REGEX','STRENDS','FILTER NOT EXISTS'];
    let h = sparql.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    h = h.replace(/(#[^\n]*)/g, '<span class="vqb-cmt">$1</span>');
    h = h.replace(/("(?:[^"\\]|\\.)*")/g, '<span class="vqb-str">$1</span>');
    h = h.replace(/(&lt;[^&\s]+&gt;)/g, '<span class="vqb-uri">$1</span>');
    h = h.replace(new RegExp(`\\b(${kws.join('|')})\\b`, 'g'), '<span class="vqb-kw">$1</span>');
    h = h.replace(/(\?[a-zA-Z_][a-zA-Z0-9_]*)/g, '<span class="vqb-var">$1</span>');
    return h;
  }

  function makeDropdownShell() {
    const dd = document.createElement('div');
    dd.className = 'vqb-dropdown';

    const searchBar = document.createElement('div');
    searchBar.className = 'vqb-dd-search';
    searchBar.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`;
    const sinput = document.createElement('input');
    sinput.autocomplete = 'off';
    searchBar.appendChild(sinput);
    dd.appendChild(searchBar);

    const body = document.createElement('div');
    body.className = 'vqb-dd-body';

    const list = document.createElement('div');
    list.className = 'vqb-dd-list';

    const info = document.createElement('div');
    info.className = 'vqb-dd-info';
    info.innerHTML = '<span class="vqb-dd-info-hint">Hover an item</span>';

    body.appendChild(list);
    body.appendChild(info);
    dd.appendChild(body);

    return { dd, sinput, list, info };
  }

  function positionDD(dd, trigger) {
    const rect = trigger.getBoundingClientRect();
    const ddW  = Math.min(400, window.innerWidth * 0.92);
    let left   = rect.left;
    if (left + ddW > window.innerWidth - 8) left = window.innerWidth - ddW - 8;
    if (left < 8) left = 8;
    const below = window.innerHeight - rect.bottom - 8;
    const above = rect.top - 8;
    if (below >= 200 || below >= above) {
      dd.style.top = (rect.bottom + 6) + 'px'; dd.style.bottom = 'auto';
    } else {
      dd.style.bottom = (window.innerHeight - rect.top + 6) + 'px'; dd.style.top = 'auto';
    }
    dd.style.left = left + 'px';
  }

  function closeDropdowns() {
    document.querySelectorAll('.vqb-dropdown.open').forEach(d => {
      d.classList.remove('open');
      if (d.parentElement === document.body) document.body.removeChild(d);
    });
    document.querySelectorAll('.vqb-pill.open').forEach(p => p.classList.remove('open'));
  }
  document.addEventListener('click', closeDropdowns);

  function makeArrow() {
    const a = document.createElement('div');
    a.className = 'vqb-arrow';
    a.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>`;
    return a;
  }

  function addCondition() {
    conditions.push({
      id: ++condSeq,
      subjectType: null, subjectVar: null,
      relation:    null,
      objectType:  null, objectVar:  null,
      filterValue: '', filterOp: 'contains', showFilter: false,
      optional: false, notExists: false, orderBy: false, orderDir: 'asc',
      combinator: 'and',
    });
    render();
  }

  function clearAll() {
    conditions = []; condSeq = 0; resetVars();
    render();
    DOM.preview().classList.remove('visible');
  }

  DOM.generate().addEventListener('click', generateSPARQL);
  DOM.clear().addEventListener('click', clearAll);
  DOM.limit().addEventListener('change', generateSPARQL);
  DOM.distinct().addEventListener('change', generateSPARQL);

  DOM.send().addEventListener('click', () => {
    const sparql = DOM.code().textContent;
    if (!sparql.trim()) return;
    const editor = document.getElementById('query-editor');
    if (editor) {
      editor.value = sparql;
      editor.dispatchEvent(new Event('input'));
      editor.scrollIntoView({ behavior: 'smooth', block: 'center' });
      if (typeof showNotification === 'function')
        showNotification('Query sent to editor — press Run Query to execute.', 'info');
    }
  });

  DOM.copy().addEventListener('click', () => {
    const text = DOM.code().textContent;
    navigator.clipboard.writeText(text).then(() => {
      if (typeof showNotification === 'function') showNotification('SPARQL copied to clipboard.', 'success');
    });
  });

  window.addEventListener('resize', closeDropdowns);
  document.querySelector('main')?.addEventListener('scroll', closeDropdowns);

  addCondition();

})();