// EXAMPLES DATA
const EXAMPLES = [
  {
    group: 'Graph Exploration',
    items: [
      {
        label: 'List All Named Graphs',
        tag: 'SELECT',
        query: `SELECT DISTINCT ?graph (COUNT(*) AS ?triples)
WHERE {
  GRAPH ?graph { ?s ?p ?o }
}
GROUP BY ?graph
ORDER BY DESC(?triples)`
      },
      {
        label: 'Count Classes per Graph',
        tag: 'SELECT',
        query: `SELECT DISTINCT ?class (COUNT(?s) AS ?count)
FROM <http://stix/>
WHERE {
  ?s a ?class .
}
GROUP BY ?class
ORDER BY DESC(?count)`
      },
      {
        label: 'All Predicates in MITRE Graph',
        tag: 'SELECT',
        query: `SELECT DISTINCT (STR(?predicate) AS ?fullPredicate) (COUNT(*) AS ?usage)
FROM <http://example.org/graph/mitre>
WHERE {
  ?s ?predicate ?o .
}
GROUP BY ?predicate
ORDER BY DESC(?usage)
LIMIT 30`
      },
      {
        label: 'Describe a Single Node',
        tag: 'SELECT',
        query: `SELECT (STR(?predicate) AS ?fullPredicate) (STR(?value) AS ?val)
FROM <http://stix/>
WHERE {
  <http://example.org/stix-uco/attack-pattern--19da6e1c-71ab-4c2f-886d-d620d09d3b5a>
      ?predicate ?value .
}`
      }
    ]
  },
  {
    group: 'ATT&CK Techniques',
    items: [
      {
        label: 'All ATT&CK Techniques',
        tag: 'SELECT',
        query: `PREFIX uco-action: <https://ontology.unifiedcyberontology.org/uco/action/>
PREFIX uco-core:   <https://ontology.unifiedcyberontology.org/uco/core/>
PREFIX stix-uco:   <http://example.org/stix-uco/>

SELECT DISTINCT ?technique ?name ?attackId ?refURL ?created
FROM <http://example.org/graph/mitre>
WHERE {
  ?technique a uco-action:ActionPattern ;
             uco-core:name ?name ;
             uco-core:objectCreatedTime ?created ;
             uco-core:externalReference ?ref .

  ?ref uco-core:externalIdentifier ?attackId ;
       uco-core:referenceURL ?refURL .

  FILTER (STRSTARTS(STR(?attackId), "T"))
  FILTER (!CONTAINS(?name, " - "))
  FILTER (!CONTAINS(?name, "@"))
}
ORDER BY ?attackId
LIMIT 100`
      },
      {
        label: 'Count Techniques by Type',
        tag: 'SELECT',
        query: `PREFIX uco-action:  <https://ontology.unifiedcyberontology.org/uco/action/>
PREFIX uco-core:    <https://ontology.unifiedcyberontology.org/uco/core/>
PREFIX stix-uco:    <http://example.org/stix-uco/>

SELECT ?ontologyClass (COUNT(DISTINCT ?technique) AS ?count)
FROM <http://example.org/graph/mitre>
WHERE {
  ?technique a uco-action:ActionPattern ;
             stix-uco:attackOntologyClass ?ontologyClass .
}
GROUP BY ?ontologyClass
ORDER BY DESC(?count)`
      },
      {
        label: 'Search Technique by Name',
        tag: 'SELECT',
        query: `PREFIX uco-action: <https://ontology.unifiedcyberontology.org/uco/action/>
PREFIX uco-core:   <https://ontology.unifiedcyberontology.org/uco/core/>

SELECT DISTINCT ?technique ?name ?attackId
FROM <http://example.org/graph/mitre>
WHERE {
  ?technique a uco-action:ActionPattern ;
             uco-core:name ?name ;
             uco-core:externalReference ?ref .

  ?ref uco-core:externalIdentifier ?attackId .

  FILTER (CONTAINS(LCASE(?name), "phishing"))
  FILTER (STRSTARTS(STR(?attackId), "T"))
}
ORDER BY ?attackId`
      },
      {
        label: 'Techniques Modified After 2020',
        tag: 'SELECT',
        query: `PREFIX uco-action: <https://ontology.unifiedcyberontology.org/uco/action/>
PREFIX uco-core:   <https://ontology.unifiedcyberontology.org/uco/core/>

SELECT DISTINCT ?name ?attackId ?modified
FROM <http://example.org/graph/mitre>
WHERE {
  ?technique a uco-action:ActionPattern ;
             uco-core:name ?name ;
             uco-core:modifiedTime ?modified ;
             uco-core:externalReference ?ref .

  ?ref uco-core:externalIdentifier ?attackId .

  FILTER (STRSTARTS(STR(?attackId), "T"))
  FILTER (!CONTAINS(?name, " - "))
  FILTER (?modified > "2020-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime>)
}
ORDER BY DESC(?modified)
LIMIT 50`
      }
    ]
  },
  {
    group: 'STIX Relationships',
    items: [
      {
        label: 'All Relationship Types',
        tag: 'SELECT',
        query: `PREFIX uco-core: <https://ontology.unifiedcyberontology.org/uco/core/>
PREFIX stix-uco: <http://example.org/stix-uco/>

SELECT DISTINCT ?relType (COUNT(*) AS ?count)
FROM <http://stix/>
WHERE {
  ?rel a uco-core:Relationship ;
       stix-uco:relationshipType ?relType .
}
GROUP BY ?relType
ORDER BY DESC(?count)`
      },
      {
        label: 'Techniques Used in NCSC Bundles',
        tag: 'SELECT',
        query: `PREFIX uco-action:  <https://ontology.unifiedcyberontology.org/uco/action/>
PREFIX uco-core:    <https://ontology.unifiedcyberontology.org/uco/core/>
PREFIX stix-uco:    <http://example.org/stix-uco/>

SELECT DISTINCT ?techniqueName ?attackId
FROM <http://example.org/graph/mitre>
FROM <http://ncsc/>
WHERE {
  ?technique a uco-action:ActionPattern ;
             uco-core:name ?techniqueName ;
             uco-core:externalReference ?ref .

  ?ref uco-core:externalIdentifier ?attackId .
  FILTER (STRSTARTS(STR(?attackId), "T"))
  FILTER (!CONTAINS(?techniqueName, " - "))
  FILTER (!CONTAINS(?techniqueName, "@"))

  ?rel a uco-core:Relationship ;
       uco-core:source ?technique .
}
ORDER BY ?attackId
LIMIT 100`
      },
      {
        label: 'Relationships with Source & Target',
        tag: 'SELECT',
        query: `PREFIX uco-core:  <https://ontology.unifiedcyberontology.org/uco/core/>
PREFIX stix-uco:  <http://example.org/stix-uco/>

SELECT ?rel ?relType ?source ?target
FROM <http://stix/>
WHERE {
  ?rel a uco-core:Relationship ;
       uco-core:source ?source ;
       uco-core:target ?target .
  OPTIONAL { ?rel stix-uco:relationshipType ?relType }
}
LIMIT 50`
      }
    ]
  },
  {
    group: 'STIX Objects',
    items: [
      {
        label: 'All Malicious Tools',
        tag: 'SELECT',
        query: `PREFIX uco-tool:  <https://ontology.unifiedcyberontology.org/uco/tool/>
PREFIX uco-core:  <https://ontology.unifiedcyberontology.org/uco/core/>

SELECT ?tool ?name ?created
FROM <http://stix/>
WHERE {
  ?tool a uco-tool:MaliciousTool ;
        uco-core:name ?name ;
        uco-core:objectCreatedTime ?created .
}
ORDER BY ?name
LIMIT 50`
      },
      {
        label: 'All Defensive Tools',
        tag: 'SELECT',
        query: `PREFIX uco-tool:  <https://ontology.unifiedcyberontology.org/uco/tool/>
PREFIX uco-core:  <https://ontology.unifiedcyberontology.org/uco/core/>

SELECT ?tool ?name ?created
FROM <http://stix/>
WHERE {
  ?tool a uco-tool:DefensiveTool ;
        uco-core:name ?name ;
        uco-core:objectCreatedTime ?created .
}
ORDER BY ?name
LIMIT 50`
      },
      {
        label: 'Organizations & Identities',
        tag: 'SELECT',
        query: `PREFIX uco-identity: <https://ontology.unifiedcyberontology.org/uco/identity/>
PREFIX uco-core:     <https://ontology.unifiedcyberontology.org/uco/core/>

SELECT ?entity ?type ?name
FROM <http://stix/>
WHERE {
  { ?entity a uco-identity:Organization . BIND("Organization" AS ?type) }
  UNION
  { ?entity a uco-identity:Identity .     BIND("Identity"     AS ?type) }
  ?entity uco-core:name ?name .
}
ORDER BY ?type ?name`
      },
      {
        label: 'Data Sources & Components',
        tag: 'SELECT',
        query: `PREFIX stix-uco: <http://example.org/stix-uco/>
PREFIX uco-core: <https://ontology.unifiedcyberontology.org/uco/core/>

SELECT ?entity ?type ?name
FROM <http://stix/>
WHERE {
  { ?entity a stix-uco:DataSource .    BIND("DataSource"    AS ?type) }
  UNION
  { ?entity a stix-uco:DataComponent . BIND("DataComponent" AS ?type) }
  OPTIONAL { ?entity uco-core:name ?name }
}
ORDER BY ?type ?name
LIMIT 50`
      }
    ]
  },
  {
    group: 'External References',
    items: [
      {
        label: 'All External References',
        tag: 'SELECT',
        query: `PREFIX uco-core: <https://ontology.unifiedcyberontology.org/uco/core/>

SELECT ?identifier ?sourceName ?url
FROM <http://stix/>
WHERE {
  ?ref a uco-core:ExternalReference ;
       uco-core:externalIdentifier ?identifier ;
       uco-core:name ?sourceName .
  OPTIONAL { ?ref uco-core:referenceURL ?url }
}
ORDER BY ?identifier
LIMIT 100`
      },
      {
        label: 'MITRE ATT&CK References Only',
        tag: 'SELECT',
        query: `PREFIX uco-core: <https://ontology.unifiedcyberontology.org/uco/core/>

SELECT ?identifier ?url
FROM <http://example.org/graph/mitre>
WHERE {
  ?ref a uco-core:ExternalReference ;
       uco-core:externalIdentifier ?identifier ;
       uco-core:referenceURL ?url .
  FILTER (STRSTARTS(STR(?identifier), "T"))
}
ORDER BY ?identifier
LIMIT 100`
      }
    ]
  },
  {
    group: 'Bundles & Groupings',
    items: [
      {
        label: 'All Bundles',
        tag: 'SELECT',
        query: `PREFIX uco-core: <https://ontology.unifiedcyberontology.org/uco/core/>

SELECT ?bundle ?name (COUNT(?obj) AS ?objectCount)
FROM <http://stix/>
WHERE {
  ?bundle a uco-core:Bundle .
  OPTIONAL { ?bundle uco-core:name ?name }
  OPTIONAL { ?bundle uco-core:object ?obj }
}
GROUP BY ?bundle ?name
ORDER BY DESC(?objectCount)`
      },
      {
        label: 'Objects Inside a Bundle',
        tag: 'SELECT',
        query: `PREFIX uco-core: <https://ontology.unifiedcyberontology.org/uco/core/>

SELECT ?object (STR(?type) AS ?objectType)
FROM <http://stix/>
WHERE {
  <http://example.org/stix-uco/bundle--b0b9c258-840b-445b-b805-e9f5fd31ed28>
      uco-core:object ?object .
  OPTIONAL { ?object a ?type }
}
LIMIT 50`
      },
      {
        label: 'All Groupings',
        tag: 'SELECT',
        query: `PREFIX uco-core: <https://ontology.unifiedcyberontology.org/uco/core/>

SELECT ?grouping ?name ?context
FROM <http://stix/>
WHERE {
  ?grouping a uco-core:Grouping .
  OPTIONAL { ?grouping uco-core:name ?name }
  OPTIONAL { ?grouping <http://example.org/stix-uco/context> ?context }
}
ORDER BY ?name
LIMIT 50`
      }
    ]
  },
  {
    group: 'ASK',
    items: [
      {
        label: 'MITRE Graph Has Data',
        tag: 'ASK',
        query: `ASK {
  GRAPH <http://example.org/graph/mitre> { ?s ?p ?o }
}`
      },
      {
        label: 'STIX Graph Has Data',
        tag: 'ASK',
        query: `ASK {
  GRAPH <http://stix/> { ?s ?p ?o }
}`
      },
      {
        label: 'Technique T1059 Exists',
        tag: 'ASK',
        query: `PREFIX uco-core: <https://ontology.unifiedcyberontology.org/uco/core/>

ASK
FROM <http://example.org/graph/mitre>
{
  ?ref uco-core:externalIdentifier "T1059" .
}`
      }
    ]
  }
];

const themeToggleBtn = document.getElementById('theme-toggle');
const ihuLogo        = document.getElementById('ihu-logo');

function applyTheme(theme) {
  if (theme === 'light') document.documentElement.setAttribute('data-theme', 'light');
  else document.documentElement.removeAttribute('data-theme');
  if (ihuLogo) ihuLogo.src = theme === 'light' ? ihuLogo.dataset.lightSrc : ihuLogo.dataset.darkSrc;
  localStorage.setItem('sparql-theme', theme);
}

themeToggleBtn.addEventListener('click', () => {
  applyTheme(document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light');
});
applyTheme(localStorage.getItem('sparql-theme') || 'dark');

let lastResults = null;
let lastVars    = [];

const editor          = document.getElementById('query-editor');
const lineNumbers     = document.getElementById('line-numbers');
const editorStatus    = document.getElementById('editor-status');
const btnRun          = document.getElementById('btn-run');
const btnClear        = document.getElementById('btn-clear');
const btnFormat       = document.getElementById('btn-format');
const btnExport       = document.getElementById('btn-export');
const endpointUrl     = document.getElementById('endpoint-url');
const endpointDisp    = document.getElementById('endpoint-display');
const responseFormat  = document.getElementById('response-format');
const resultsPanel    = document.getElementById('results-panel');
const resultsBody     = document.getElementById('results-body');
const resultCount     = document.getElementById('result-count');
const elapsedTime     = document.getElementById('elapsed-time');
const notification    = document.getElementById('notification');
const notifMsg        = document.getElementById('notification-msg');
const notifDot        = document.getElementById('notification-dot');
const btnExamples     = document.getElementById('btn-examples');
const examplesDropdown= document.getElementById('examples-dropdown');
const examplesWrap    = document.getElementById('examples-wrap');
const examplesSearch  = document.getElementById('examples-search');
const searchClear     = document.getElementById('examples-search-clear');
const examplesList    = document.getElementById('examples-list');
const previewCode     = document.getElementById('preview-code');
const previewTitle    = document.getElementById('preview-title');
const previewUseBtn   = document.getElementById('preview-use-btn');

// ── EXAMPLES DROPDOWN ─────────────────────────────────────────
let activeExample = null;

function tagClass(tag) {
  return { SELECT:'tag-select', ASK:'tag-ask', CONSTRUCT:'tag-construct', DESCRIBE:'tag-describe' }[tag] || 'tag-select';
}

function highlightQuery(query) {
  const kws = ['SELECT','DISTINCT','WHERE','FILTER','OPTIONAL','UNION','LIMIT','OFFSET',
    'ORDER BY','GROUP BY','HAVING','PREFIX','BASE','GRAPH','SERVICE','BIND','VALUES',
    'MINUS','REDUCED','FROM','NAMED','CONSTRUCT','ASK','DESCRIBE','AS','COUNT','SUM',
    'AVG','MIN','MAX','STRSTARTS','CONTAINS','LCASE','UCASE','LANG','STR','CONCAT',
    'COALESCE','IF','BOUND','EXISTS','NOT EXISTS','REGEX'];
  let h = query.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  h = h.replace(/(#[^\n]*)/g,'<span class="cmt">$1</span>');
  h = h.replace(/("(?:[^"\\]|\\.)*")/g,'<span class="str">$1</span>');
  h = h.replace(new RegExp(`\\b(${kws.join('|')})\\b`,'g'),'<span class="kw">$1</span>');
  h = h.replace(/(\?[a-zA-Z_][a-zA-Z0-9_]*)/g,'<span class="var">$1</span>');
  return h;
}

function renderExamplesList(filter = '') {
  examplesList.innerHTML = '';
  const q = filter.toLowerCase();
  let total = 0;
  EXAMPLES.forEach(group => {
    const filtered = group.items.filter(item =>
      item.label.toLowerCase().includes(q) || item.tag.toLowerCase().includes(q) || item.query.toLowerCase().includes(q));
    if (!filtered.length) return;
    total += filtered.length;
    const gl = document.createElement('div'); gl.className = 'dropdown-group-label';
    gl.textContent = group.group; examplesList.appendChild(gl);
    filtered.forEach(item => {
      const row = document.createElement('div');
      row.className = 'dropdown-item' + (activeExample === item ? ' active' : '');
      row.innerHTML = `<span class="dropdown-item-label">${item.label}</span>
        <span class="dropdown-item-tag ${tagClass(item.tag)}">${item.tag}</span>
        <svg class="dropdown-item-preview-icon" width="13" height="13" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
          <circle cx="12" cy="12" r="3"/></svg>`;
      row.addEventListener('mouseenter', () => showPreview(item, row));
      row.addEventListener('click', () => useExample(item));
      examplesList.appendChild(row);
    });
  });
  if (!total) examplesList.innerHTML = `<div class="dropdown-no-results">No examples match "${filter}"</div>`;
}

function showPreview(item, rowEl) {
  examplesList.querySelectorAll('.dropdown-item').forEach(r => r.classList.remove('active'));
  rowEl.classList.add('active');
  activeExample = item;
  previewTitle.textContent = item.label;
  previewCode.innerHTML = highlightQuery(item.query);
}

function useExample(item) {
  editor.value = item.query;
  updateLineNumbers(); updateStatus();
  closeDropdown();
  showNotification(`Loaded: ${item.label}`, 'info');
}

function openDropdown() {
  examplesDropdown.classList.add('open');
  btnExamples.classList.add('open');
  examplesSearch.focus();
  if (!activeExample) {
    const first = examplesList.querySelector('.dropdown-item');
    if (first) first.dispatchEvent(new MouseEvent('mouseenter'));
  }
}
function closeDropdown() {
  examplesDropdown.classList.remove('open');
  btnExamples.classList.remove('open');
}

btnExamples.addEventListener('click', e => { e.stopPropagation(); examplesDropdown.classList.contains('open') ? closeDropdown() : openDropdown(); });
document.addEventListener('click', e => { if (!examplesWrap.contains(e.target)) closeDropdown(); });

examplesSearch.addEventListener('input', () => {
  const v = examplesSearch.value;
  searchClear.classList.toggle('visible', v.length > 0);
  activeExample = null; renderExamplesList(v);
  const first = examplesList.querySelector('.dropdown-item');
  if (first) first.dispatchEvent(new MouseEvent('mouseenter'));
});

searchClear.addEventListener('click', () => {
  examplesSearch.value = ''; searchClear.classList.remove('visible');
  activeExample = null; renderExamplesList(''); examplesSearch.focus();
});

previewUseBtn.addEventListener('click', () => { if (activeExample) useExample(activeExample); });
renderExamplesList();
setTimeout(() => {
  const first = examplesList.querySelector('.dropdown-item');
  if (first) first.dispatchEvent(new MouseEvent('mouseenter'));
}, 0);

function updateLineNumbers() {
  const lines = editor.value.split('\n').length;
  lineNumbers.textContent = Array.from({length: lines}, (_, i) => i + 1).join('\n');
  lineNumbers.scrollTop = editor.scrollTop;
}
function updateStatus() {
  const before = editor.value.substring(0, editor.selectionStart).split('\n');
  editorStatus.textContent = `Ln ${before.length}, Col ${before[before.length-1].length+1}`;
}

editor.addEventListener('input',  () => { updateLineNumbers(); updateStatus(); });
editor.addEventListener('click',  updateStatus);
editor.addEventListener('keyup',  updateStatus);
editor.addEventListener('scroll', () => { lineNumbers.scrollTop = editor.scrollTop; });
editor.addEventListener('keydown', e => {
  if (e.key === 'Tab') {
    e.preventDefault();
    const s = editor.selectionStart, end = editor.selectionEnd;
    editor.value = editor.value.substring(0,s)+'  '+editor.value.substring(end);
    editor.selectionStart = editor.selectionEnd = s+2;
    updateLineNumbers();
  }
  if ((e.ctrlKey||e.metaKey) && e.key === 'Enter') { e.preventDefault(); runQuery(); }
});

endpointUrl.addEventListener('input', () => {
  try { const u = new URL(endpointUrl.value); endpointDisp.textContent = u.host+u.pathname; }
  catch { endpointDisp.textContent = endpointUrl.value; }
});

btnRun.addEventListener('click', runQuery);
btnClear.addEventListener('click', () => { editor.value=''; updateLineNumbers(); updateStatus(); hideResults(); });
btnFormat.addEventListener('click', () => {
  const f = editor.value.trim()
    .replace(/\b(SELECT|CONSTRUCT|ASK|DESCRIBE|WHERE|FILTER|OPTIONAL|UNION|LIMIT|OFFSET|ORDER BY|GROUP BY|HAVING|PREFIX|BASE|GRAPH|SERVICE|BIND|VALUES|MINUS|DISTINCT|REDUCED|FROM|NAMED)\b/gi, m=>'\n'+m.toUpperCase())
    .replace(/\{\s*/g,'{\n  ').replace(/\s*\}/g,'\n}')
    .split('\n').map(l=>l.trim()).filter(Boolean).join('\n');
  editor.value = f; updateLineNumbers();
});
btnExport.addEventListener('click', exportCSV);

async function runQuery() {
  const query = editor.value.trim();
  if (!query) { showNotification('Query is empty.','error'); return; }
  const url = endpointUrl.value.trim();
  if (!url) { showNotification('No endpoint URL specified.','error'); return; }

  setLoading(true); showResultsPanel(); showLoading(); lastResults = null;
  const t0 = performance.now();
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type':'application/sparql-query', 'Accept':'application/sparql-results+json' },
      body: query
    });
    elapsedTime.textContent = `${((performance.now()-t0)/1000).toFixed(3)}s`;
    if (!res.ok) { const e = await res.text().catch(()=>''); throw new Error(`HTTP ${res.status} ${res.statusText}${e?': '+e.substring(0,200):''}`); }
    const data = await res.json();
    renderResults(data);
  } catch(err) {
    elapsedTime.textContent = `${((performance.now()-t0)/1000).toFixed(3)}s`;
    showError(err.message);
  } finally { setLoading(false); }
}

function renderResults(data) {
  if (data.boolean !== undefined) {
    lastResults = null; lastVars = [];
    resultCount.style.display = 'none';
    resultsBody.innerHTML = '';
    resultsBody.appendChild(makeStateBox(
      data.boolean ? 'success' : 'error', 'ASK Result',
      data.boolean ? 'true — The pattern exists.' : 'false — No match found.',
      data.boolean
        ? '<polyline points="20 6 9 17 4 12"/>'
        : '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>'));
    hideGraph();
    return;
  }
  if (!data.results?.bindings) { showError('Unexpected response format.'); return; }

  const vars = data.head?.vars || [];
  const rows = data.results.bindings;
  lastVars = vars; lastResults = rows;

  resultCount.textContent = `${rows.length} row${rows.length!==1?'s':''}`;
  resultCount.style.display = '';

  if (rows.length === 0) {
    resultsBody.innerHTML = '';
    resultsBody.appendChild(makeStateBox('info','No Results','Query succeeded but returned 0 rows.',
      '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>'));
    hideGraph();
    return;
  }

  const wrap  = document.createElement('div'); wrap.className = 'table-wrap';
  const table = document.createElement('table');
  const thead = document.createElement('thead');
  const hRow  = document.createElement('tr');
  const thN   = document.createElement('th'); thN.textContent = '#'; hRow.appendChild(thN);
  vars.forEach(v => { const th=document.createElement('th'); th.textContent='?'+v; hRow.appendChild(th); });
  thead.appendChild(hRow); table.appendChild(thead);

  const tbody = document.createElement('tbody');
  rows.forEach((row,i) => {
    const tr = document.createElement('tr');
    const tdN = document.createElement('td'); tdN.textContent = i+1; tr.appendChild(tdN);
    vars.forEach(v => {
      const td = document.createElement('td');
      const b  = row[v];
      if (!b) { td.textContent='—'; td.className='cell-null'; }
      else if (b.type==='uri') {
        td.textContent=shortenUri(b.value); td.className='cell-uri';
        td.title=b.value; td.addEventListener('click',()=>window.open(b.value,'_blank'));
      } else if (b.type==='bnode') {
        td.textContent='_:'+b.value; td.className='cell-bnode';
      } else {
        let d=b.value;
        if (b['xml:lang']) d+=` @${b['xml:lang']}`;
        else if (b.datatype) d+=` (${shortenUri(b.datatype)})`;
        td.textContent=d; td.className='cell-literal'; td.title=b.value;
      }
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });

  table.appendChild(tbody); wrap.appendChild(table);
  resultsBody.innerHTML = ''; resultsBody.appendChild(wrap);
  showNotification(`${rows.length} result${rows.length!==1?'s':''} returned.`, 'success');

  buildGraph(vars, rows);
}

function makeStateBox(type, title, desc, svgInner) {
  const box=document.createElement('div'); box.className='state-box';
  const ico=document.createElement('div'); ico.className=`state-icon ${type}`;
  ico.innerHTML=`<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">${svgInner}</svg>`;
  const t=document.createElement('div'); t.className='state-title'; t.textContent=title;
  const d=document.createElement('div'); d.className='state-desc';  d.textContent=desc;
  box.appendChild(ico); box.appendChild(t); box.appendChild(d);
  return box;
}

function shortenUri(uri) {
  const prefixes = {
    'https://ontology.unifiedcyberontology.org/uco/action/':'uco-action:',
    'https://ontology.unifiedcyberontology.org/uco/core/':'uco-core:',
    'https://ontology.unifiedcyberontology.org/uco/tool/':'uco-tool:',
    'https://ontology.unifiedcyberontology.org/uco/identity/':'uco-identity:',
    'https://ontology.unifiedcyberontology.org/uco/marking/':'uco-marking:',
    'https://ontology.unifiedcyberontology.org/uco/analysis/':'uco-analysis:',
    'http://example.org/stix-uco/':'stix-uco:',
    'http://example.org/ontology#':'ex:',
    'http://www.w3.org/1999/02/22-rdf-syntax-ns#':'rdf:',
    'http://www.w3.org/2000/01/rdf-schema#':'rdfs:',
    'http://www.w3.org/2002/07/owl#':'owl:',
    'http://www.w3.org/2001/XMLSchema#':'xsd:',
    'http://schema.org/':'schema:',
  };
  for (const [ns,prefix] of Object.entries(prefixes)) if (uri.startsWith(ns)) return prefix+uri.slice(ns.length);
  if (uri.length>60) {
    const cut=Math.max(uri.lastIndexOf('/'),uri.lastIndexOf('#'));
    if (cut>10) return '…'+uri.slice(cut);
  }
  return uri;
}

function setLoading(on) { btnRun.disabled=on; btnRun.classList.toggle('loading',on); }
function showResultsPanel() { resultsPanel.classList.add('visible'); resultCount.style.display='none'; elapsedTime.textContent=''; }
function hideResults()       { resultsPanel.classList.remove('visible'); hideGraph(); }
function showLoading()       { resultsBody.innerHTML=`<div class="loading-state"><div class="loading-ring"></div><div class="loading-text">Executing query…</div></div>`; }

function showError(msg) {
  resultCount.style.display='none'; resultsBody.innerHTML='';
  resultsBody.appendChild(makeStateBox('error','Query Error',msg,
    '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>'));
  showNotification('Query failed. See results panel.','error');
  hideGraph();
}

let notifTimer;
function showNotification(msg, type='info') {
  notifMsg.textContent=msg;
  notifDot.style.background=type==='error'?'var(--red)':type==='success'?'var(--green)':'var(--accent)';
  notification.className='notification'+(type==='error'?' error':'');
  notification.classList.add('show');
  clearTimeout(notifTimer);
  notifTimer=setTimeout(()=>notification.classList.remove('show'),3200);
}

function exportCSV() {
  if (!lastResults||!lastVars.length) return;
  const rows=lastResults.map(row=>lastVars.map(v=>{const b=row[v];if(!b)return'';return`"${b.value.replace(/"/g,'""')}"`;}).join(','));
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([[lastVars.join(','),...rows].join('\n')],{type:'text/csv'}));
  a.download='sparql-results.csv'; a.click();
}


// d3 library

const graphPanel     = document.getElementById('graph-panel');
const graphSvg       = document.getElementById('graph-svg');
const graphTooltip   = document.getElementById('graph-tooltip');
const graphInfo      = document.getElementById('graph-info');
const graphInfoTitle = document.getElementById('graph-info-title');
const graphInfoBody  = document.getElementById('graph-info-body');
const graphInfoClose = document.getElementById('graph-info-close');
const graphNodeCount = document.getElementById('graph-node-count');
const graphLegend    = document.getElementById('graph-legend');
const btnGraphFit    = document.getElementById('btn-graph-fit');
const btnGraphReset  = document.getElementById('btn-graph-reset');
const sliderDistance = document.getElementById('slider-distance');
const sliderCharge   = document.getElementById('slider-charge');

let simulation = null;
let svgRoot    = null;
let gMain      = null;

const NODE_COLORS = {
  uri:     { fill: '#3d62c8', stroke: '#5b8af5' },
  literal: { fill: '#1f6b46', stroke: '#4ec9a0' },
  bnode:   { fill: '#6a3fad', stroke: '#b48ef5' },
};

function nodeRadius(d) { return Math.min(14 + (d.degree||1)*1.2, 28); }
function nodeLabel(d)  { const s=d.shortLabel||d.label||''; return s.length>20?s.slice(0,18)+'…':s; }

function buildGraphData(vars, rows) {
  const sVar = vars.find(v=>/^s(ubj(ect)?)?$/i.test(v))||vars[0];
  const pVar = vars.find(v=>/^p(red(icate)?)?$/i.test(v))||vars[1];
  const oVar = vars.find(v=>/^o(bj(ect)?)?$/i.test(v))||vars[2];
  const hasSPO = sVar&&pVar&&oVar;

  const nodesMap=new Map(), links=[];

  function getOrCreate(binding,id) {
    if (!binding) return null;
    if (nodesMap.has(id)) return nodesMap.get(id);
    const node={id,label:binding.value,shortLabel:shortenUri(binding.value),
      type:binding.type||'uri',fullValue:binding.value,
      lang:binding['xml:lang']||null,datatype:binding.datatype||null,degree:0};
    nodesMap.set(id,node); return node;
  }

  if (hasSPO) {
    rows.forEach(row=>{
      const sB=row[sVar],pB=row[pVar],oB=row[oVar];
      if(!sB||!oB) return;
      const sN=getOrCreate(sB,`${sB.type}::${sB.value}`);
      const oN=getOrCreate(oB,`${oB.type}::${oB.value}`);
      if(!sN||!oN) return;
      sN.degree++; oN.degree++;
      links.push({source:sN.id,target:oN.id,label:pB?shortenUri(pB.value):'?p',fullPred:pB?.value||''});
    });
  } else {
    rows.forEach((row,i)=>{
      const rowNodes=[];
      vars.forEach(v=>{const b=row[v];if(!b)return;const n=getOrCreate(b,`${b.type}::${b.value}`);if(n)rowNodes.push(n);});
      for(let i=0;i<rowNodes.length-1;i++){rowNodes[i].degree++;rowNodes[i+1].degree++;links.push({source:rowNodes[i].id,target:rowNodes[i+1].id,label:`row${i+1}`,fullPred:''});}
    });
  }

  return {nodes:Array.from(nodesMap.values()),links};
}

function buildGraph(vars,rows) {
  if (typeof d3==='undefined') return;
  graphPanel.classList.add('visible');

  const MAX=400;
  if (rows.length>MAX) showNotification(`Graph limited to first ${MAX} rows.`,'info');
  const {nodes,links}=buildGraphData(vars,rows.slice(0,MAX));
  if (!nodes.length){hideGraph();return;}

  graphNodeCount.textContent=`${nodes.length} nodes · ${links.length} edges`;
  buildLegend(nodes);
  if (simulation) simulation.stop();

  const svgEl=graphSvg;
  const W=svgEl.clientWidth||800, H=svgEl.clientHeight||520;
  d3.select(svgEl).selectAll('*').remove();
  svgRoot=d3.select(svgEl);

  const defs=svgRoot.append('defs');
  defs.append('marker').attr('id','graph-arrow').attr('viewBox','0 0 10 10')
    .attr('refX',22).attr('refY',5).attr('markerWidth',6).attr('markerHeight',6)
    .attr('orient','auto-start-reverse').append('path')
    .attr('d','M2 1L8 5L2 9').attr('fill','none').attr('stroke','#2e3347')
    .attr('stroke-width','1.5').attr('stroke-linecap','round').attr('stroke-linejoin','round');

  const zoom=d3.zoom().scaleExtent([0.1,8]).on('zoom',e=>gMain.attr('transform',e.transform));
  svgRoot.call(zoom).on('dblclick.zoom',null);
  gMain=svgRoot.append('g');

  simulation=d3.forceSimulation(nodes)
    .force('link',d3.forceLink(links).id(d=>d.id).distance(+sliderDistance.value).strength(0.6))
    .force('charge',d3.forceManyBody().strength(+sliderCharge.value))
    .force('center',d3.forceCenter(W/2,H/2))
    .force('collision',d3.forceCollide().radius(d=>nodeRadius(d)+8))
    .alphaDecay(0.02);

  const linkSel=gMain.append('g').selectAll('line').data(links).join('line')
    .attr('class','graph-link').attr('marker-end','url(#graph-arrow)');

  const linkLabelSel=gMain.append('g').selectAll('text').data(links).join('text')
    .attr('class','graph-link-label')
    .text(d=>d.label.length>22?d.label.slice(0,20)+'…':d.label);

  const nodeSel=gMain.append('g').selectAll('g').data(nodes).join('g')
    .attr('class','graph-node')
    .call(d3.drag().on('start',dragStart).on('drag',dragged).on('end',dragEnd));

  nodeSel.append('circle')
    .attr('r',d=>nodeRadius(d))
    .attr('fill',d=>NODE_COLORS[d.type]?.fill||'#3d62c8')
    .attr('stroke',d=>NODE_COLORS[d.type]?.stroke||'#5b8af5');

  nodeSel.append('text').text(d=>nodeLabel(d)).attr('dy',d=>nodeRadius(d)+12).attr('font-size','10px');

  nodeSel
    .on('mouseenter',(e,d)=>showTooltip(e,d))
    .on('mousemove', e=>moveTooltip(e))
    .on('mouseleave',()=>hideTooltip())
    .on('click',(e,d)=>{e.stopPropagation();selectNode(d,nodeSel,linkSel);});

  svgRoot.on('click',()=>deselectAll(nodeSel,linkSel));

  simulation.on('tick',()=>{
    linkSel
      .attr('x1',d=>d.source.x).attr('y1',d=>d.source.y)
      .attr('x2',d=>{const dx=d.target.x-d.source.x,dy=d.target.y-d.source.y,dist=Math.sqrt(dx*dx+dy*dy)||1;return d.target.x-(dx/dist)*nodeRadius(d.target);})
      .attr('y2',d=>{const dx=d.target.x-d.source.x,dy=d.target.y-d.source.y,dist=Math.sqrt(dx*dx+dy*dy)||1;return d.target.y-(dy/dist)*nodeRadius(d.target);});
    linkLabelSel.attr('x',d=>(d.source.x+d.target.x)/2).attr('y',d=>(d.source.y+d.target.y)/2);
    nodeSel.attr('transform',d=>`translate(${d.x},${d.y})`);
  });

  sliderDistance.oninput=()=>{simulation.force('link').distance(+sliderDistance.value);simulation.alpha(0.3).restart();};
  sliderCharge.oninput=()=>{simulation.force('charge').strength(+sliderCharge.value);simulation.alpha(0.3).restart();};
  btnGraphFit.onclick=()=>fitGraph(zoom,W,H,nodes);
  btnGraphReset.onclick=()=>{nodes.forEach(n=>{delete n.x;delete n.y;delete n.vx;delete n.vy;});simulation.alpha(1).restart();};
  graphInfoClose.onclick=()=>graphInfo.classList.remove('visible');
}

function dragStart(e,d){if(!e.active)simulation.alphaTarget(0.3).restart();d.fx=d.x;d.fy=d.y;}
function dragged(e,d){d.fx=e.x;d.fy=e.y;}
function dragEnd(e,d){if(!e.active)simulation.alphaTarget(0);d.fx=null;d.fy=null;}

function showTooltip(event,d){
  graphTooltip.innerHTML=`<div class="tooltip-type ${d.type}">${d.type==='uri'?'URI':d.type==='literal'?'Literal':'Blank Node'}</div><div>${d.shortLabel}</div>`;
  graphTooltip.classList.add('visible');moveTooltip(event);
}
function moveTooltip(event){
  const r=graphSvg.getBoundingClientRect();
  graphTooltip.style.left=(event.clientX-r.left+12)+'px';
  graphTooltip.style.top=(event.clientY-r.top-10)+'px';
}
function hideTooltip(){graphTooltip.classList.remove('visible');}

function selectNode(d,nodeSel,linkSel){
  linkSel.classed('highlighted',l=>l.source.id===d.id||l.target.id===d.id);
  nodeSel.classed('selected',n=>n.id===d.id);
  const connLinks=(simulation.force('link').links()||[]).filter(l=>l.source.id===d.id||l.target.id===d.id);
  let html=`<div class="info-row"><div class="info-label">Value</div>
    <div class="info-value ${d.type}" ${d.type==='uri'?`onclick="window.open('${d.fullValue}','_blank')"`:''}>${d.fullValue}</div></div>`;
  if(d.lang) html+=`<div class="info-row"><div class="info-label">Language</div><div class="info-value">@${d.lang}</div></div>`;
  if(d.datatype) html+=`<div class="info-row"><div class="info-label">Datatype</div><div class="info-value">${shortenUri(d.datatype)}</div></div>`;
  html+=`<div class="info-row"><div class="info-label">Connections</div><div class="info-value">${connLinks.length}</div></div>`;
  if(connLinks.length){
    html+=`<div class="info-connections">`;
    connLinks.slice(0,8).forEach(l=>{
      const isOut=l.source.id===d.id,other=isOut?l.target:l.source,dir=isOut?'→':'←';
      html+=`<div class="info-conn-item">${dir} <span class="info-conn-pred">${l.label}</span> ${other.shortLabel}</div>`;
    });
    if(connLinks.length>8) html+=`<div class="info-conn-item">…and ${connLinks.length-8} more</div>`;
    html+=`</div>`;
  }
  graphInfoTitle.textContent=d.type==='uri'?'URI':d.type==='literal'?'Literal':'Blank Node';
  graphInfoBody.innerHTML=html;
  graphInfo.classList.add('visible');
}

function deselectAll(nodeSel,linkSel){
  nodeSel.classed('selected',false);linkSel.classed('highlighted',false);
  graphInfo.classList.remove('visible');
}

function fitGraph(zoom,W,H,nodes){
  const xs=nodes.map(n=>n.x).filter(Boolean),ys=nodes.map(n=>n.y).filter(Boolean);
  if(!xs.length) return;
  const minX=Math.min(...xs),maxX=Math.max(...xs),minY=Math.min(...ys),maxY=Math.max(...ys);
  const gw=maxX-minX||1,gh=maxY-minY||1;
  const scale=Math.min(0.9*W/gw,0.9*H/gh,4);
  svgRoot.transition().duration(500)
    .call(zoom.transform,d3.zoomIdentity.translate(W/2-scale*(minX+gw/2),H/2-scale*(minY+gh/2)).scale(scale));
}

function buildLegend(nodes){
  const types=[...new Set(nodes.map(n=>n.type))];
  const labels={uri:'URI',literal:'Literal',bnode:'Blank node'};
  graphLegend.innerHTML=types.map(t=>`<div class="graph-legend-item"><div class="graph-legend-dot" style="background:${NODE_COLORS[t]?.fill||'#5b8af5'}"></div><span>${labels[t]||t}</span></div>`).join('');
}

function hideGraph(){
  graphPanel.classList.remove('visible');
  if(simulation){simulation.stop();simulation=null;}
}

updateLineNumbers();
updateStatus();

const copyEl = document.querySelector('.footer-copy');
if (copyEl) copyEl.innerHTML = `&copy; ${new Date().getFullYear()} TripleView Studio. Developed by International Hellenic University.`;