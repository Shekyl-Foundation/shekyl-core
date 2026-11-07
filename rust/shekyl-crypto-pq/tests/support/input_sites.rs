// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Where a domain constant is applied, and whether that function carries
//! the input type the registry names.
//!
//! Included by `domain_binding` via `#[path]`. No tests live here.

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::Mutex;

use quote::ToTokens;
use syn::visit::Visit;

/// Field types of every struct or enum that carries a given name.
///
/// The outer vec is one entry per definition. A name is unfolded only
/// when that vec holds a single definition.
pub type TypeDefinitions = BTreeMap<String, Vec<Vec<String>>>;

/// One parsed workspace: production functions, and each struct's fields
/// keyed by the type's own name.
#[derive(Clone, Debug, Default)]
pub struct Workspace {
    files: BTreeMap<String, FileSites>,
    /// Every definition of a type name. Unfolding uses a name only when
    /// the workspace has exactly one definition, so two unrelated `Input`
    /// structs cannot lend each other fields.
    structs: TypeDefinitions,
}

#[derive(Clone, Debug, Default)]
struct FileSites {
    sites: Vec<Site>,
}

#[derive(Clone, Debug)]
struct Site {
    name: String,
    self_type: Option<String>,
    /// Parameter, typed-let, and typed-closure types, tokens spaced.
    inputs: Vec<String>,
    mentions: HashSet<String>,
    calls: Vec<Call>,
}

#[derive(Clone, Debug)]
struct Call {
    path: String,
    last: String,
    /// String and byte-string arguments, decoded.
    literals: Vec<String>,
}

/// One production function that applies `konst`.
#[derive(Clone, Debug)]
pub struct Application {
    pub file: String,
    pub function: String,
    /// The function's composition carries `rust_type`.
    pub carries: bool,
}

/// Parse `files` (repository-relative) through `read`. A file that does not
/// parse is named in the error list; the rest of the workspace is kept.
pub fn collect(
    read: &dyn Fn(&str) -> Option<String>,
    files: &[String],
) -> (Workspace, Vec<String>) {
    let mut ws = Workspace::default();
    let mut errors = Vec::new();
    for file in files {
        let Some(source) = read(file) else {
            continue;
        };
        match parsed(&source) {
            Ok(parsed) => {
                for (name, fields) in parsed.structs {
                    ws.structs.entry(name).or_default().push(fields);
                }
                ws.files.insert(
                    file.clone(),
                    FileSites {
                        sites: parsed.sites,
                    },
                );
            }
            Err(e) => errors.push(format!("{file} does not parse: {e}")),
        }
    }
    (ws, errors)
}

/// Every production function that applies `konst`.
///
/// An ident konst is applied where a function's body names it. A
/// parenthetical konst `(Path::new)` is applied where a function calls
/// that path with the row's literal among the arguments. Anything else
/// (an inline prefix, a prose note) has no site this walk can see.
pub fn applications(
    ws: &Workspace,
    konst: &str,
    literal: &str,
    rust_type: &str,
) -> Vec<Application> {
    let mut out = Vec::new();
    for (file, body) in &ws.files {
        for (index, site) in body.sites.iter().enumerate() {
            if !site_applies(site, konst, literal) {
                continue;
            }
            out.push(Application {
                file: file.clone(),
                function: site.display(),
                carries: composition_carries(body, index, rust_type, &ws.structs),
            });
        }
    }
    out
}

fn site_applies(site: &Site, konst: &str, literal: &str) -> bool {
    if let Some(path) = call_path(konst) {
        return site
            .calls
            .iter()
            .any(|call| call.path == path && call.literals.iter().any(|lit| lit == literal));
    }
    is_ident(konst) && site.mentions.contains(konst)
}

/// `(RecommendedTranscript::new)` → `RecommendedTranscript::new`.
/// A parenthetical note that is not a path returns `None`.
fn call_path(konst: &str) -> Option<String> {
    let inner = konst.strip_prefix('(')?.strip_suffix(')')?.trim();
    let parts: Vec<&str> = inner.split("::").map(str::trim).collect();
    if parts.len() >= 2 && parts.iter().all(|part| is_ident(part)) {
        Some(parts.join("::"))
    } else {
        None
    }
}

fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {
            chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
        }
        _ => false,
    }
}

impl Call {
    /// Whether `site` is the function this call names.
    ///
    /// An unqualified call names a free function in the same file.
    /// `Type::method` names a method of that type. A qualifier that
    /// starts in lowercase is a module, and names a free function.
    fn reaches(&self, site: &Site) -> bool {
        if site.name != self.last {
            return false;
        }
        match self.path.rsplit_once("::") {
            None => site.self_type.is_none(),
            Some((parent, _)) => {
                let qualifier = parent.rsplit("::").next().unwrap_or(parent);
                match site.self_type.as_deref() {
                    Some(ty) => ty == qualifier,
                    None => qualifier.starts_with(|c: char| c.is_ascii_lowercase()),
                }
            }
        }
    }
}

/// The applying function carries the type when the type appears in its
/// inputs, in a same-file function it calls by path, or in another method
/// of the same type. A hasher whose `begin` binds the domain and whose
/// `fold` takes the value is one site. A typed parameter on a function
/// this composition does not reach is not.
fn composition_carries(
    file: &FileSites,
    index: usize,
    rust_type: &str,
    structs: &TypeDefinitions,
) -> bool {
    let mut stack = vec![index];
    if let Some(self_type) = &file.sites[index].self_type {
        for (i, site) in file.sites.iter().enumerate() {
            if site.self_type.as_ref() == Some(self_type) {
                stack.push(i);
            }
        }
    }
    let mut seen = HashSet::new();
    while let Some(i) = stack.pop() {
        if !seen.insert(i) {
            continue;
        }
        let site = &file.sites[i];
        if site
            .inputs
            .iter()
            .any(|ty| type_carries(ty, rust_type, structs))
        {
            return true;
        }
        for call in &site.calls {
            for (j, other) in file.sites.iter().enumerate() {
                if call.reaches(other) {
                    stack.push(j);
                }
            }
        }
    }
    false
}

/// Whether `ty` (tokens spaced the way `quote` prints them) contains
/// `name`: the type itself, a reference, a slice, an array, a `Vec` or
/// other generic argument, a tuple element, or a field of a workspace
/// type that has one definition.
pub fn type_carries(ty: &str, name: &str, structs: &TypeDefinitions) -> bool {
    fn walk(ty: &str, name: &str, structs: &TypeDefinitions, seen: &mut HashSet<String>) -> bool {
        let mut rest = ty.trim();
        if rest.is_empty() {
            return false;
        }
        loop {
            if let Some(stripped) = rest.strip_prefix('&') {
                rest = stripped.trim_start();
                continue;
            }
            if let Some(stripped) = rest.strip_prefix("mut ") {
                rest = stripped.trim_start();
                continue;
            }
            if let Some(stripped) = rest.strip_prefix('\'') {
                let end = stripped
                    .find(|c: char| !(c == '_' || c.is_ascii_alphanumeric()))
                    .unwrap_or(stripped.len());
                rest = stripped[end..].trim_start();
                continue;
            }
            break;
        }
        if rest.is_empty() {
            return false;
        }
        match rest.chars().next() {
            Some('[') => {
                let inner = matching_close(rest, '[', ']');
                let elem = inner.split(';').next().unwrap_or(inner);
                return walk(elem, name, structs, seen);
            }
            Some('(') => {
                let inner = matching_close(rest, '(', ')');
                return split_top(inner)
                    .into_iter()
                    .any(|part| walk(part, name, structs, seen));
            }
            _ => {}
        }
        let (path, args) = split_generics(rest);
        let seg = path.rsplit("::").next().unwrap_or(path).trim();
        if seg == name {
            return true;
        }
        if let Some(args) = args {
            let carried = split_top(args).into_iter().any(|arg| {
                let value = arg
                    .split_once('=')
                    .map(|(_, v)| v.trim())
                    .unwrap_or(arg.trim());
                walk(value, name, structs, seen)
            });
            if carried {
                return true;
            }
        }
        if !is_ident(seg) || !seen.insert(seg.to_string()) {
            return false;
        }
        match structs.get(seg) {
            Some(defs) if defs.len() == 1 => {
                defs[0].iter().any(|field| walk(field, name, structs, seen))
            }
            _ => false,
        }
    }
    walk(ty, name, structs, &mut HashSet::new())
}

fn matching_close(s: &str, open: char, close: char) -> &str {
    let mut depth = 0i32;
    for (i, c) in s.char_indices() {
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return &s[open.len_utf8()..i];
            }
        }
    }
    s.get(open.len_utf8()..).unwrap_or("")
}

fn split_top(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '<' | '(' | '[' => depth += 1,
            '>' | ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                out.push(&s[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

fn split_generics(s: &str) -> (&str, Option<&str>) {
    let mut paren = 0i32;
    for (i, c) in s.char_indices() {
        match c {
            '(' | '[' => paren += 1,
            ')' | ']' => paren -= 1,
            '<' if paren == 0 => {
                let inner = matching_close(&s[i..], '<', '>');
                return (s[..i].trim(), Some(inner));
            }
            _ => {}
        }
    }
    (s.trim(), None)
}

#[derive(Clone, Debug, Default)]
struct Parsed {
    sites: Vec<Site>,
    structs: BTreeMap<String, Vec<String>>,
}

fn parsed(source: &str) -> Result<Parsed, String> {
    static CACHE: Mutex<Option<std::collections::HashMap<(u64, usize), Parsed>>> = Mutex::new(None);
    let mut hasher = DefaultHasher::new();
    source.hash(&mut hasher);
    let key = (hasher.finish(), source.len());
    let mut guard = CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let cache = guard.get_or_insert_with(std::collections::HashMap::new);
    if let Some(hit) = cache.get(&key) {
        return Ok(hit.clone());
    }
    let file = syn::parse_file(source).map_err(|e| e.to_string())?;
    let mut collector = Collector::default();
    collector.visit_file(&file);
    let parsed = Parsed {
        sites: collector.sites,
        structs: collector.structs,
    };
    cache.insert(key, parsed.clone());
    Ok(parsed)
}

#[derive(Default)]
struct Collector {
    stack: Vec<Site>,
    impl_self: Vec<Option<String>>,
    sites: Vec<Site>,
    structs: BTreeMap<String, Vec<String>>,
}

impl Collector {
    fn enter(&mut self, sig: &syn::Signature) {
        let self_type = self.impl_self.last().and_then(Clone::clone);
        let mut site = Site {
            name: sig.ident.to_string(),
            self_type: self_type.clone(),
            inputs: Vec::new(),
            mentions: HashSet::new(),
            calls: Vec::new(),
        };
        if sig.receiver().is_some() {
            site.inputs.extend(self_type);
        }
        self.stack.push(site);
    }

    fn leave(&mut self) {
        if let Some(site) = self.stack.pop() {
            self.sites.push(site);
        }
    }

    fn note_macro(&mut self, mac: &syn::Macro) {
        let mut idents = Vec::new();
        for word in mac
            .tokens
            .to_string()
            .split(|c: char| !(c == '_' || c.is_ascii_alphanumeric()))
        {
            if is_ident(word) {
                idents.push(word.to_string());
            }
        }
        if let Some(site) = self.stack.last_mut() {
            site.mentions.extend(idents);
        }
    }
}

impl Site {
    fn display(&self) -> String {
        match &self.self_type {
            Some(ty) => format!("{ty}::{}", self.name),
            None => self.name.clone(),
        }
    }
}

fn skips_as_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg") && squash(&attr.meta).contains("test"))
    })
}

fn squash(tokens: impl ToTokens) -> String {
    tokens
        .to_token_stream()
        .to_string()
        .split_whitespace()
        .collect()
}

fn spaced(tokens: impl ToTokens) -> String {
    tokens.to_token_stream().to_string()
}

fn field_types(fields: &syn::Fields) -> Vec<String> {
    fields.iter().map(|field| spaced(&field.ty)).collect()
}

fn type_ident(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(path) => path.path.segments.last().map(|seg| seg.ident.to_string()),
        syn::Type::Reference(reference) => type_ident(&reference.elem),
        syn::Type::Group(group) => type_ident(&group.elem),
        syn::Type::Paren(paren) => type_ident(&paren.elem),
        _ => None,
    }
}

fn push_lit(expr: &syn::Expr, out: &mut Vec<String>) {
    match expr {
        syn::Expr::Lit(lit) => match &lit.lit {
            syn::Lit::Str(text) => out.push(text.value()),
            syn::Lit::ByteStr(text) => {
                if let Ok(decoded) = String::from_utf8(text.value()) {
                    out.push(decoded);
                }
            }
            _ => {}
        },
        syn::Expr::Paren(paren) => push_lit(&paren.expr, out),
        syn::Expr::Group(group) => push_lit(&group.expr, out),
        _ => {}
    }
}

impl<'ast> Visit<'ast> for Collector {
    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        if !skips_as_test(&module.attrs) {
            syn::visit::visit_item_mod(self, module);
        }
    }

    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        if skips_as_test(&function.attrs) {
            return;
        }
        self.enter(&function.sig);
        syn::visit::visit_item_fn(self, function);
        self.leave();
    }

    fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
        if skips_as_test(&function.attrs) {
            return;
        }
        self.enter(&function.sig);
        syn::visit::visit_impl_item_fn(self, function);
        self.leave();
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if skips_as_test(&item.attrs) {
            return;
        }
        self.impl_self.push(type_ident(&item.self_ty));
        syn::visit::visit_item_impl(self, item);
        self.impl_self.pop();
    }

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        if skips_as_test(&item.attrs) {
            return;
        }
        self.structs
            .entry(item.ident.to_string())
            .or_default()
            .extend(field_types(&item.fields));
    }

    fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
        if skips_as_test(&item.attrs) {
            return;
        }
        let mut fields = Vec::new();
        for variant in &item.variants {
            fields.extend(field_types(&variant.fields));
        }
        self.structs
            .entry(item.ident.to_string())
            .or_default()
            .extend(fields);
    }

    fn visit_pat_type(&mut self, pat: &'ast syn::PatType) {
        if let Some(site) = self.stack.last_mut() {
            site.inputs.push(spaced(&pat.ty));
        }
        syn::visit::visit_pat_type(self, pat);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if let Some(site) = self.stack.last_mut() {
            for segment in &path.path.segments {
                site.mentions.insert(segment.ident.to_string());
            }
        }
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            let parts: Vec<String> = path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect();
            if let Some(last) = parts.last().cloned() {
                let mut literals = Vec::new();
                for arg in &call.args {
                    push_lit(arg, &mut literals);
                }
                let mut qualified = parts.join("::");
                if let Some(rest) = qualified.strip_prefix("Self::") {
                    if let Some(ty) = self.stack.last().and_then(|site| site.self_type.clone()) {
                        qualified = format!("{ty}::{rest}");
                    }
                }
                if let Some(site) = self.stack.last_mut() {
                    site.calls.push(Call {
                        path: qualified,
                        last,
                        literals,
                    });
                }
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if !self.stack.is_empty() {
            self.note_macro(mac);
        }
    }
}
