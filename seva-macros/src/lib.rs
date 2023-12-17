extern crate proc_macro;

use proc_macro2::Literal;

use proc_macro2::{TokenStream, TokenTree};
use quote::quote;
use syn::{
    parse_macro_input, Attribute, Data, DataEnum, DeriveInput, Error, Generics,
    Ident, Meta, Result,
};

#[proc_macro_derive(HttpStatusCode, attributes(code))]
pub fn http_status_code_derive(
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive(&input)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}
#[proc_macro_derive(MimeType, attributes(mime_type, mime_ext))]
pub fn mime_type_derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_mime_type(&input)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}
fn from_syn(node: &DeriveInput) -> Result<Enum> {
    match &node.data {
        Data::Enum(data) => Enum::from_syn(node, data),
        _ => Err(Error::new_spanned(
            node,
            "only enums are supported as http status codes",
        )),
    }
}
fn derive_mime_type(node: &DeriveInput) -> Result<TokenStream> {
    let input = from_syn(node)?;

    let ty = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let mime_impls =
        input
            .variants
            .iter()
            .filter(|v| v.mime_type.is_some())
            .map(|variant| {
                let mime_type: String =
                    extract_mime_type(&variant.mime_type.unwrap().meta);
                let variant = &variant.ident;

                quote! {
                    #ty::#variant => #mime_type,
                }
            });
    let from_ext_impls = input.variants.iter().map(|v| {
        let var = &v.ident;
        let ext: String = if v.mime_ext.is_none() {
            format!("{}", var).to_lowercase()
        } else {
            extract_mime_ext(&v.mime_ext.unwrap().meta)
        };
        quote! {
            #ext => Some(#ty::#var),
        }
    });

    Ok(quote! {
        impl #impl_generics ::core::fmt::Display for #ty #ty_generics #where_clause {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                let s = match &self {
                     #(#mime_impls)*
                };
                write!(f, "{}", s)
            }
        }
        impl #impl_generics #ty #ty_generics #where_clause {
            ///Get mime type from file extension
            pub fn from_ext(ext: String) -> Option<#ty> {
                match ext.to_lowercase().as_str() {
                    #(#from_ext_impls)*
                    _ => None
                }
            }
        }
    })
}
fn derive(node: &DeriveInput) -> Result<TokenStream> {
    let input = from_syn(node)?;

    let ty = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let status_code_impls =
        input
            .variants
            .iter()
            .filter(|v| v.code.is_some())
            .map(|variant| {
                let code: Literal = match &variant.code.unwrap().meta {
                    Meta::List(ml) => {
                        let tok = ml
                            .tokens
                            .clone()
                            .into_iter()
                            .next()
                            .expect("missing status code number");
                        match tok {
                            TokenTree::Literal(lit) => lit,
                            _ => unreachable!(),
                        }
                    }
                    _ => unreachable!(),
                };
                let variant = &variant.ident;

                quote! {
                    #ty::#variant => #code,
                }
            });
    let status_msg_impls = input.variants.iter().map(|var| {
        let variant = &var.ident;
        let name = format!("{}", variant);
        quote! {
            #ty::#variant => #name,
        }
    });
    Ok(quote! {
        impl #impl_generics ::core::convert::From<#ty> for u16 #ty_generics #where_clause {
            fn from(value: #ty) -> u16 {
                match value {
                    #(#status_code_impls)*
                }
            }
        }
        impl #impl_generics ::core::fmt::Display for #ty #ty_generics #where_clause {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                let s = match &self {
                     #(#status_msg_impls)*
                };
                write!(f, "{}", s)
            }
        }
    })
}
struct Enum<'a> {
    ident: Ident,
    generics: &'a Generics,
    variants: Vec<Variant<'a>>,
}

impl<'a> Enum<'a> {
    fn from_syn(node: &'a DeriveInput, data: &'a DataEnum) -> Result<Self> {
        let variants = data
            .variants
            .iter()
            .map(|node| {
                let variant = Variant::from_syn(node)?;

                Ok(variant)
            })
            .collect::<Result<_>>()?;
        Ok(Enum {
            ident: node.ident.clone(),
            generics: &node.generics,
            variants,
        })
    }
}

struct Variant<'a> {
    code: Option<&'a Attribute>,
    mime_type: Option<&'a Attribute>,
    mime_ext: Option<&'a Attribute>,
    ident: Ident,
}

impl<'a> Variant<'a> {
    fn from_syn(node: &'a syn::Variant) -> Result<Self> {
        Ok(Variant {
            code: get_code_attr(&node.attrs),
            mime_type: get_mime_type_attr(&node.attrs),
            mime_ext: get_mime_ext_attr(&node.attrs),
            ident: node.ident.clone(),
        })
    }
}

fn get_code_attr(input: &[Attribute]) -> Option<&Attribute> {
    input.iter().find(|&attr| attr.path().is_ident("code"))
}

fn get_mime_type_attr(input: &[Attribute]) -> Option<&Attribute> {
    input.iter().find(|&attr| attr.path().is_ident("mime_type"))
}

fn get_mime_ext_attr(input: &[Attribute]) -> Option<&Attribute> {
    input.iter().find(|&attr| attr.path().is_ident("mime_ext"))
}

fn extract_mime_ext(meta: &Meta) -> String {
    let mut s = String::new();
    match meta {
        Meta::List(ml) => {
            for tok in ml.tokens.clone() {
                match tok {
                    TokenTree::Literal(lit) => s.push_str(&format!("{}", lit)),
                    TokenTree::Ident(id) => s.push_str(&format!("{}", id)),
                    _ => unreachable!(),
                }
            }
        }
        _ => unreachable!(),
    }
    s
}

fn extract_mime_type(meta: &Meta) -> String {
    match meta {
        Meta::List(ml) => {
            let mt = flatten_token_stream(ml.tokens.clone());

            if mt.is_empty() {
                panic!("Got empty mime type");
            }
            mt
        }
        _ => unreachable!(),
    }
}

fn flatten_token_stream(ts: TokenStream) -> String {
    let mut tokens = String::new();
    for tt in ts {
        match tt {
            TokenTree::Group(g) => {
                let toks = flatten_token_stream(g.stream());
                tokens.push_str(&toks);
            }
            TokenTree::Ident(i) => tokens.push_str(&format!("{}", i)),
            TokenTree::Punct(p) => tokens.push_str(&format!("{}", p.as_char())),
            TokenTree::Literal(l) => tokens.push_str(&format!("{}", l)),
        }
    }
    tokens
}
