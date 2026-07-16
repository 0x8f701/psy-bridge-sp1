fn main() {
    let args = sp1_build::BuildArgs {
        binaries: vec![
            "block-transition".to_owned(),
            "block-transition-testnet".to_owned(),
        ],
        ..Default::default()
    };
    sp1_build::build_program_with_args("../program", args);
}
