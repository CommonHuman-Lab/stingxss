"""
StingXSS — engine/crawler.py
Multi-threaded BFS web crawler.

Discovers links and HTML forms within a target origin.
Respects same-origin constraint, max depth, and max page limits.

Returns:
  - A list of (url, method, params) tuples representing discovered
    injectable surfaces.
  - A list of all crawled URLs (for DOM scanning).
"""

from __future__ import annotations

import re
import urllib.parse as up
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .injector import Injector

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class FormTarget:
  url:    str
  method: str                   # GET | POST
  params: Dict[str, str]        # {name: default_value}
  action: str                   # resolved form action URL


@dataclass
class CrawlResult:
  visited_urls:  List[str]          = field(default_factory=list)
  form_targets:  List[FormTarget]   = field(default_factory=list)
  url_params:    List[Tuple[str, List[str]]] = field(default_factory=list)  # (url, [param_names])
  page_sources:  Dict[str, str]     = field(default_factory=dict)   # url -> html body


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def crawl(
  start_url:   str,
  injector:    Injector,
  max_pages:   int = 50,
  max_depth:   int = 3,
  threads:     int = 5,
  same_origin: bool = True,
) -> CrawlResult:
  """
  BFS crawl starting from `start_url`.
  Returns a CrawlResult with all discovered pages, forms, and URL params.
  """
  result   = CrawlResult()
  visited:  Set[str] = set()
  queue:    deque    = deque()   # (url, depth)
  queue.append((_normalise(start_url), 0))

  origin = injector.get_base_url(start_url)

  with ThreadPoolExecutor(max_workers=threads) as pool:
    while queue and len(visited) < max_pages:
      # Drain current BFS level into a batch
      batch = []
      while queue and len(batch) < threads * 2:
        url, depth = queue.popleft()
        norm = _normalise(url)
        if norm in visited:
          continue
        if same_origin and not injector.same_origin(norm, start_url):
          continue
        visited.add(norm)
        batch.append((norm, depth))

      if not batch:
        break

      futures = {pool.submit(_fetch_page, url, injector): (url, depth)
                 for url, depth in batch}

      for future in as_completed(futures):
        url, depth = futures[future]
        try:
          html, links, forms = future.result()
        except Exception:
          continue

        result.visited_urls.append(url)
        result.page_sources[url] = html

        # Collect URL params
        params = injector.get_params(url)
        if params:
          result.url_params.append((url, params))

        # Collect form targets
        for form in forms:
          result.form_targets.append(form)

        # Enqueue new links
        if depth < max_depth:
          for link in links:
            norm = _normalise(link)
            if norm not in visited:
              queue.append((norm, depth + 1))

  return result


# ---------------------------------------------------------------------------
# Page fetching and parsing
# ---------------------------------------------------------------------------

def _fetch_page(
  url: str,
  injector: Injector,
) -> Tuple[str, List[str], List[FormTarget]]:
  """
  GET `url`, extract links and forms.
  Returns (html_body, [absolute_links], [FormTarget])
  """
  try:
    resp = injector.get(url)
  except Exception:
    return "", [], []

  if resp.status_code >= 400:
    return "", [], []

  ct = resp.headers.get("content-type", "")
  if "html" not in ct and "javascript" not in ct:
    return "", [], []

  html  = resp.text
  links = _extract_links(html, url)
  forms = _extract_forms(html, url)

  return html, links, forms


def _extract_links(html: str, base_url: str) -> List[str]:
  """Extract and resolve all <a href> and relevant resource URLs."""
  hrefs = re.findall(r'<a[^>]+href\s*=\s*["\']([^"\'#][^"\']*)["\']', html, re.IGNORECASE)
  links = []
  for href in hrefs:
    href = href.strip()
    if href.startswith("javascript:") or href.startswith("mailto:"):
      continue
    try:
      abs_url = up.urljoin(base_url, href)
      # Strip fragment
      parsed = up.urlparse(abs_url)
      abs_url = up.urlunparse(parsed._replace(fragment=""))
      links.append(abs_url)
    except Exception:
      continue
  return links


def _extract_forms(html: str, base_url: str) -> List[FormTarget]:
  """
  Extract all HTML forms, returning action URL, method, and input fields.
  """
  forms = []
  # Match each <form ...>...</form>
  for form_match in re.finditer(r"<form([^>]*)>(.*?)</form>", html, re.DOTALL | re.IGNORECASE):
    attrs_str = form_match.group(1)
    body_str  = form_match.group(2)

    # Action
    action_m = re.search(r'action\s*=\s*["\']([^"\']*)["\']', attrs_str, re.IGNORECASE)
    action_raw = action_m.group(1) if action_m else ""
    try:
      action = up.urljoin(base_url, action_raw) if action_raw else base_url
    except Exception:
      action = base_url

    # Method
    method_m = re.search(r'method\s*=\s*["\']([^"\']*)["\']', attrs_str, re.IGNORECASE)
    method = (method_m.group(1) if method_m else "GET").upper()

    # Inputs
    params: Dict[str, str] = {}
    for inp in re.finditer(
      r'<input([^>]*)>', body_str, re.IGNORECASE | re.DOTALL
    ):
      inp_attrs = inp.group(1)
      name_m  = re.search(r'name\s*=\s*["\']([^"\']*)["\']', inp_attrs, re.IGNORECASE)
      value_m = re.search(r'value\s*=\s*["\']([^"\']*)["\']', inp_attrs, re.IGNORECASE)
      type_m  = re.search(r'type\s*=\s*["\']([^"\']*)["\']', inp_attrs, re.IGNORECASE)
      input_type = (type_m.group(1) if type_m else "text").lower()
      if input_type in ("submit", "button", "image", "reset", "hidden"):
        continue  # skip non-data inputs
      if name_m:
        params[name_m.group(1)] = value_m.group(1) if value_m else ""

    # Textareas
    for ta in re.finditer(
      r'<textarea[^>]*name\s*=\s*["\']([^"\']*)["\']', body_str, re.IGNORECASE
    ):
      params[ta.group(1)] = ""

    # Select elements
    for sel in re.finditer(
      r'<select[^>]*name\s*=\s*["\']([^"\']*)["\']', body_str, re.IGNORECASE
    ):
      params[sel.group(1)] = ""

    if params:
      forms.append(FormTarget(url=action, method=method, params=params, action=action))

  return forms


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise(url: str) -> str:
  """Strip trailing slash and fragment, lowercase scheme+host."""
  try:
    p = up.urlparse(url)
    normalised = up.urlunparse((
      p.scheme.lower(),
      p.netloc.lower(),
      p.path.rstrip("/") or "/",
      p.params,
      p.query,
      "",  # no fragment
    ))
    return normalised
  except Exception:
    return url
