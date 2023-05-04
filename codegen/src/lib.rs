use ark_serialize::CanonicalSerialize;
use ministark::air::AirConfig;
use ministark::constraints::AlgebraicItem;
use ministark::constraints::CompositionConstraint;
use ministark::constraints::CompositionItem;
use ministark::Air;
use num_traits::Pow;
use proc_macro2::Ident;
use proc_macro2::TokenStream;
use quote::format_ident;
use quote::quote;
use quote::TokenStreamExt;
use std::cell::RefCell;
use std::ops::Add;
use std::ops::Div;
use std::ops::Mul;
use std::ops::Neg;
use std::sync::Mutex;

static NEXT_ID_COUNTER: Mutex<usize> = Mutex::new(0);

pub fn uid() -> usize {
    let mut lock = NEXT_ID_COUNTER.lock().unwrap();
    let id = *lock;
    *lock += 1;
    id
}

#[derive(Clone, Debug)]
struct EvalItem<'a> {
    symbol: proc_macro2::TokenStream,
    program: &'a RefCell<proc_macro2::TokenStream>,
}

impl<'a> EvalItem<'a> {
    /// Generates a unique identifier
    pub fn next_ident(&self) -> Ident {
        format_ident!("tmp{}", uid())
    }
}

impl<'a> Add for EvalItem<'a> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let next_ident = self.next_ident();
        let lhs_ident = self.symbol;
        let rhs_ident = rhs.symbol;
        self.program.borrow_mut().append_all(quote! {
            let #next_ident = #lhs_ident + #rhs_ident;
        });
        Self {
            symbol: quote!(#next_ident),
            program: self.program,
        }
    }
}

impl<'a> Mul for EvalItem<'a> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let next_ident = self.next_ident();
        let lhs_ident = self.symbol;
        let rhs_ident = rhs.symbol;
        self.program.borrow_mut().append_all(quote! {
            let #next_ident = #lhs_ident * #rhs_ident;
        });
        Self {
            symbol: quote!(#next_ident),
            program: self.program,
        }
    }
}

impl<'a> Div for EvalItem<'a> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        let next_ident = self.next_ident();
        let lhs_ident = self.symbol;
        let rhs_ident = rhs.symbol;
        self.program.borrow_mut().append_all(quote! {
            let #next_ident = #lhs_ident / #rhs_ident;
        });
        Self {
            symbol: quote!(#next_ident),
            program: self.program,
        }
    }
}

impl<'a> Neg for EvalItem<'a> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let next_ident = self.next_ident();
        let in_ident = self.symbol;
        self.program.borrow_mut().append_all(quote! {
            let #next_ident = -#in_ident;
        });
        Self {
            symbol: quote!(#next_ident),
            program: self.program,
        }
    }
}

impl<'a> Pow<usize> for EvalItem<'a> {
    type Output = Self;

    fn pow(self, exp: usize) -> Self::Output {
        let exp = exp as u64;
        let next_ident = self.next_ident();
        let in_ident = self.symbol;
        self.program.borrow_mut().append_all(quote! {
            let #next_ident = #in_ident.pow([#exp]);
        });
        Self {
            symbol: quote!(#next_ident),
            program: self.program,
        }
    }
}

/// Generates a rust function that evaluates the constraints for a specific
/// trace length Output is of the form `(function identifier, function tokens)`
pub fn gen_evaluator_for_len<C: AirConfig>(trace_len: usize) -> (Ident, TokenStream) {
    let evaluator_ident = format_ident!("eval_constraint_with_trace_len_{}", trace_len);
    let mut constants = quote!();
    let inner_loop = RefCell::new(quote!());
    let base_column_range = Air::<C>::base_column_range();
    let extension_column_range = Air::<C>::extension_column_range();
    let constraints = C::constraints(trace_len);
    let eval_expr = CompositionConstraint::new(&constraints, trace_len);

    use AlgebraicItem::*;
    use CompositionItem::*;
    let last_symbol = eval_expr
        .graph_eval(&mut |leaf| match *leaf {
            Item(X) => EvalItem {
                symbol: quote!(FieldVariant::<C::Fp, C::Fq>::Fp(x)),
                program: &inner_loop,
            },
            Item(Trace(col_idx, offset)) => {
                let row_idx = quote!((i as isize + step * #offset).rem_euclid(n as isize) as usize);
                let symbol = if base_column_range.contains(&col_idx) {
                    let column = quote!(base_trace_lde[#col_idx]);
                    quote!(FieldVariant::<C::Fp, C::Fq>::Fp(#column[#row_idx]))
                } else if extension_column_range.contains(&col_idx) {
                    let extension_col_idx = col_idx - C::NUM_BASE_COLUMNS;
                    let column = quote!(extension_trace_lde[#extension_col_idx]);
                    quote!(FieldVariant::<C::Fp, C::Fq>::Fq(#column[#row_idx]))
                } else {
                    panic!("invalid column {col_idx}")
                };
                EvalItem {
                    symbol,
                    program: &inner_loop,
                }
            }
            Item(Challenge(i)) => EvalItem {
                symbol: quote!(FieldVariant::<C::Fp, C::Fq>::Fq(challenges[#i])),
                program: &inner_loop,
            },
            Item(Hint(i)) => EvalItem {
                symbol: quote!(FieldVariant::<C::Fp, C::Fq>::Fq(hints[#i])),
                program: &inner_loop,
            },
            Item(Constant(c)) => {
                let ident = format_ident!("tmp{}", uid());
                // serialize the constants
                let mut bytes = Vec::new();
                c.serialize_compressed(&mut bytes).unwrap();
                constants.append_all(quote! {
                    let #ident: FieldVariant<C::Fp, C::Fq> =
                        FieldVariant::deserialize_compressed([#(#bytes),*].as_slice()).unwrap();
                });
                EvalItem {
                    symbol: quote!(#ident),
                    program: &inner_loop,
                }
            }
            CompositionCoeff(i) => EvalItem {
                symbol: quote!(FieldVariant::<C::Fp, C::Fq>::Fq(composition_constraint_coeffs[#i])),
                program: &inner_loop,
            },
        })
        .symbol;

    let inner_loop = RefCell::take(&inner_loop);
    let evaluator = quote! {
        fn #evaluator_ident<C: ministark::air::AirConfig>(
            challenges: &ministark::challenges::Challenges<C::Fq>,
            hints: &[C::Fq],
            composition_constraint_coeffs: &[C::Fq],
            lde_step: usize,
            x_lde: gpu_poly::GpuVec<C::Fp>,
            base_trace_lde: &ministark::Matrix<C::Fp>,
            extension_trace_lde: Option<&ministark::Matrix<C::Fq>>,
        ) -> ministark::Matrix<C::Fq> {
            use ark_ff::Zero;
            use gpu_poly::prelude::PageAlignedAllocator;
            use ark_serialize::CanonicalDeserialize;
            let n = x_lde.len();
            let step = lde_step as isize;
            let mut result = Vec::with_capacity_in(n, PageAlignedAllocator);
            result.resize(n, C::Fq::zero());
            let extension_trace_lde = extension_trace_lde.unwrap();
            #constants
            for (i, (v, x)) in result.iter_mut().zip(x_lde).enumerate() {
                #inner_loop
                *v = #last_symbol.as_fq();
            }
            Matrix::new(vec![result])
        }
    };

    (evaluator_ident, evaluator)
}

pub fn gen_evaluator<C: AirConfig>() -> TokenStream {
    let trace_lengths = (4..24).map(|k| 1 << k);
    let (eval_idents, evaluators): (Vec<Ident>, Vec<TokenStream>) = trace_lengths
        .clone()
        .map(|n| gen_evaluator_for_len::<C>(n))
        .unzip();

    quote! {
        #(#evaluators)*
        fn eval<C: ministark::air::AirConfig>(
            challenges: &ministark::challenges::Challenges<C::Fq>,
            hints: &[C::Fq],
            composition_constraint_coeffs: &[C::Fq],
            lde_step: usize,
            x_lde: GpuVec<C::Fp>,
            base_trace_lde: &ministark::Matrix<C::Fp>,
            extension_trace_lde: Option<&ministark::Matrix<C::Fq>>,
        ) -> ministark::Matrix<C::Fq> {
            match x_lde.len() {
                #(#trace_lengths => #eval_idents::<C>(
                    challenges,
                    hints,
                    composition_constraint_coeffs,
                    lde_step,
                    x_lde,
                    base_trace_lde,
                    extension_trace_lde,
                ),)*
                _ => unreachable!()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_poly::EvaluationDomain;
    use ark_poly::Radix2EvaluationDomain;
    use layouts::layout6;

    #[test]
    fn codegen_test() {
        let trace_len = 1 << 4;
        println!("YO: {}", gen_evaluator::<layout6::AirConfig>());
        println!("{:?}", 5.cmp(&0));
    }
}
