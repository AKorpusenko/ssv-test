package simcontract

//go:generate solcjs simcontract.sol --abi --bin -o build
//go:generate abigen --abi build/simcontract_sol_Callable.abi --bin build/simcontract_sol_Callable.bin --pkg simcontract --out simcontract.go
