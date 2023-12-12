extern crate proc_macro;

use proc_macro2::Literal;
use proc_macro2::Span;
use proc_macro2::TokenStream;
use proc_macro2::TokenTree;
use quote::quote;
use syn::Meta;
use syn::{
    parse_macro_input, Attribute, Data, DataEnum, DeriveInput, Error, Generics, Ident, Result,
};

#[proc_macro_derive(HttpStatusCode, attributes(code))]
pub fn http_status_code_derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive(&input)
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
fn derive(node: &DeriveInput) -> Result<TokenStream> {
    let input = from_syn(node)?;

    let ty = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let status_code_impls = input.variants.iter().map(|variant| {
        let code: Literal = match &variant.code.meta {
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
        let span = Span::call_site();
        let variants = data
            .variants
            .iter()
            .map(|node| {
                let variant = Variant::from_syn(node, span)?;

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
    code: &'a Attribute,
    ident: Ident,
}

impl<'a> Variant<'a> {
    fn from_syn(node: &'a syn::Variant, span: Span) -> Result<Self> {
        Ok(Variant {
            code: get_code_attr(&node.attrs, span)?,
            ident: node.ident.clone(),
        })
    }
}

fn get_code_attr(input: &[Attribute], span: Span) -> Result<&Attribute> {
    for attr in input {
        if attr.path().is_ident("code") {
            return Ok(attr);
        }
    }
    Err(Error::new(span, "missing code attribute!"))
}
