// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package abis

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// TaskManagerUpgradeableTask is an auto generated low-level Go binding around an user-defined struct.
type TaskManagerUpgradeableTask struct {
	PartnerId       *big.Int
	DepositAddress  common.Address
	State           uint8
	TimelockEndTime uint32
	Deadline        uint32
	Amount          *big.Int
	FundingTxOut    uint32
	TimelockTxOut   uint32
	FundingTxHash   [32]byte
	TimelockTxHash  [32]byte
	WitnessScript   [7][32]byte
	BtcAddress      [2][32]byte
	BtcPubKey       [2][32]byte
}

// TaskManagerContractMetaData contains all meta data concerning the TaskManagerContract contract.
var TaskManagerContractMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[{\"name\":\"_bitcoin\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_bridge\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"receive\",\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"ADMIN_ROLE\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"DEFAULT_ADMIN_ROLE\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"RELAYER_ROLE\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"bitcoin\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"bridge\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"burn\",\"inputs\":[{\"name\":\"_taskId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"cancelTask\",\"inputs\":[{\"name\":\"_taskId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"forceBurn\",\"inputs\":[{\"name\":\"_taskId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"getPartnerTasks\",\"inputs\":[{\"name\":\"_partnerId\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256[]\",\"internalType\":\"uint256[]\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getRoleAdmin\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getTask\",\"inputs\":[{\"name\":\"_index\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"tuple\",\"internalType\":\"structTaskManagerUpgradeable.Task\",\"components\":[{\"name\":\"partnerId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"depositAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"state\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"timelockEndTime\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"deadline\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"amount\",\"type\":\"uint128\",\"internalType\":\"uint128\"},{\"name\":\"fundingTxOut\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"timelockTxOut\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"fundingTxHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"timelockTxHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"witnessScript\",\"type\":\"bytes32[7]\",\"internalType\":\"bytes32[7]\"},{\"name\":\"btcAddress\",\"type\":\"bytes32[2]\",\"internalType\":\"bytes32[2]\"},{\"name\":\"btcPubKey\",\"type\":\"bytes32[2]\",\"internalType\":\"bytes32[2]\"}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"grantRole\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"hasPendingTask\",\"inputs\":[{\"name\":\"depositAddress\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"hasRole\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"initTimelockTx\",\"inputs\":[{\"name\":\"_taskId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"_timelockTxHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"_txOut\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"_witnessScript\",\"type\":\"bytes32[7]\",\"internalType\":\"bytes32[7]\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"initialize\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"partnerBeacon\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"partnerTasks\",\"inputs\":[{\"name\":\"partnerId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"processTimelockTx\",\"inputs\":[{\"name\":\"_taskId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"height\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"proof\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"},{\"name\":\"_index\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"receiveFunds\",\"inputs\":[{\"name\":\"_taskId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"_amount\",\"type\":\"uint128\",\"internalType\":\"uint128\"},{\"name\":\"_fundingTxHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"_txOut\",\"type\":\"uint32\",\"internalType\":\"uint32\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"renounceRole\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"callerConfirmation\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"revokeRole\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"setupTask\",\"inputs\":[{\"name\":\"_partnerId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"_depositAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_timelockEndTime\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"_deadline\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"_amount\",\"type\":\"uint128\",\"internalType\":\"uint128\"},{\"name\":\"_btcAddress\",\"type\":\"bytes32[2]\",\"internalType\":\"bytes32[2]\"},{\"name\":\"_btcPubKey\",\"type\":\"bytes32[2]\",\"internalType\":\"bytes32[2]\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"supportsInterface\",\"inputs\":[{\"name\":\"interfaceId\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"tasks\",\"inputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"partnerId\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"depositAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"state\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"timelockEndTime\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"deadline\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"amount\",\"type\":\"uint128\",\"internalType\":\"uint128\"},{\"name\":\"fundingTxOut\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"timelockTxOut\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"fundingTxHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"timelockTxHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"verifyMerkleProof\",\"inputs\":[{\"name\":\"root\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"proof\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"},{\"name\":\"leaf\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"index\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"pure\"},{\"type\":\"event\",\"name\":\"Burned\",\"inputs\":[{\"name\":\"taskId\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"FundsReceived\",\"inputs\":[{\"name\":\"taskId\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"},{\"name\":\"fundingTxHash\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"},{\"name\":\"txOut\",\"type\":\"uint32\",\"indexed\":false,\"internalType\":\"uint32\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Initialized\",\"inputs\":[{\"name\":\"version\",\"type\":\"uint64\",\"indexed\":false,\"internalType\":\"uint64\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"RoleAdminChanged\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"previousAdminRole\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"newAdminRole\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"RoleGranted\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"account\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"sender\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"RoleRevoked\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"account\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"sender\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"TaskCancelled\",\"inputs\":[{\"name\":\"taskId\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"TaskCreated\",\"inputs\":[{\"name\":\"taskId\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"TimelockInitialized\",\"inputs\":[{\"name\":\"taskId\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"},{\"name\":\"timelockTxHash\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"},{\"name\":\"txOut\",\"type\":\"uint32\",\"indexed\":false,\"internalType\":\"uint32\"},{\"name\":\"witnessScript\",\"type\":\"bytes32[7]\",\"indexed\":false,\"internalType\":\"bytes32[7]\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"TimelockProcessed\",\"inputs\":[{\"name\":\"taskId\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"error\",\"name\":\"AccessControlBadConfirmation\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"AccessControlUnauthorizedAccount\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"neededRole\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]},{\"type\":\"error\",\"name\":\"InvalidInitialization\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"NotInitializing\",\"inputs\":[]}]",
}

// TaskManagerContractABI is the input ABI used to generate the binding from.
// Deprecated: Use TaskManagerContractMetaData.ABI instead.
var TaskManagerContractABI = TaskManagerContractMetaData.ABI

// TaskManagerContract is an auto generated Go binding around an Ethereum contract.
type TaskManagerContract struct {
	TaskManagerContractCaller     // Read-only binding to the contract
	TaskManagerContractTransactor // Write-only binding to the contract
	TaskManagerContractFilterer   // Log filterer for contract events
}

// TaskManagerContractCaller is an auto generated read-only Go binding around an Ethereum contract.
type TaskManagerContractCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TaskManagerContractTransactor is an auto generated write-only Go binding around an Ethereum contract.
type TaskManagerContractTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TaskManagerContractFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type TaskManagerContractFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TaskManagerContractSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type TaskManagerContractSession struct {
	Contract     *TaskManagerContract // Generic contract binding to set the session for
	CallOpts     bind.CallOpts        // Call options to use throughout this session
	TransactOpts bind.TransactOpts    // Transaction auth options to use throughout this session
}

// TaskManagerContractCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type TaskManagerContractCallerSession struct {
	Contract *TaskManagerContractCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts              // Call options to use throughout this session
}

// TaskManagerContractTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type TaskManagerContractTransactorSession struct {
	Contract     *TaskManagerContractTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts              // Transaction auth options to use throughout this session
}

// TaskManagerContractRaw is an auto generated low-level Go binding around an Ethereum contract.
type TaskManagerContractRaw struct {
	Contract *TaskManagerContract // Generic contract binding to access the raw methods on
}

// TaskManagerContractCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type TaskManagerContractCallerRaw struct {
	Contract *TaskManagerContractCaller // Generic read-only contract binding to access the raw methods on
}

// TaskManagerContractTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type TaskManagerContractTransactorRaw struct {
	Contract *TaskManagerContractTransactor // Generic write-only contract binding to access the raw methods on
}

// NewTaskManagerContract creates a new instance of TaskManagerContract, bound to a specific deployed contract.
func NewTaskManagerContract(address common.Address, backend bind.ContractBackend) (*TaskManagerContract, error) {
	contract, err := bindTaskManagerContract(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &TaskManagerContract{TaskManagerContractCaller: TaskManagerContractCaller{contract: contract}, TaskManagerContractTransactor: TaskManagerContractTransactor{contract: contract}, TaskManagerContractFilterer: TaskManagerContractFilterer{contract: contract}}, nil
}

// NewTaskManagerContractCaller creates a new read-only instance of TaskManagerContract, bound to a specific deployed contract.
func NewTaskManagerContractCaller(address common.Address, caller bind.ContractCaller) (*TaskManagerContractCaller, error) {
	contract, err := bindTaskManagerContract(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &TaskManagerContractCaller{contract: contract}, nil
}

// NewTaskManagerContractTransactor creates a new write-only instance of TaskManagerContract, bound to a specific deployed contract.
func NewTaskManagerContractTransactor(address common.Address, transactor bind.ContractTransactor) (*TaskManagerContractTransactor, error) {
	contract, err := bindTaskManagerContract(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &TaskManagerContractTransactor{contract: contract}, nil
}

// NewTaskManagerContractFilterer creates a new log filterer instance of TaskManagerContract, bound to a specific deployed contract.
func NewTaskManagerContractFilterer(address common.Address, filterer bind.ContractFilterer) (*TaskManagerContractFilterer, error) {
	contract, err := bindTaskManagerContract(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &TaskManagerContractFilterer{contract: contract}, nil
}

// bindTaskManagerContract binds a generic wrapper to an already deployed contract.
func bindTaskManagerContract(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := TaskManagerContractMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_TaskManagerContract *TaskManagerContractRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _TaskManagerContract.Contract.TaskManagerContractCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_TaskManagerContract *TaskManagerContractRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.TaskManagerContractTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_TaskManagerContract *TaskManagerContractRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.TaskManagerContractTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_TaskManagerContract *TaskManagerContractCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _TaskManagerContract.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_TaskManagerContract *TaskManagerContractTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_TaskManagerContract *TaskManagerContractTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.contract.Transact(opts, method, params...)
}

// ADMINROLE is a free data retrieval call binding the contract method 0x75b238fc.
//
// Solidity: function ADMIN_ROLE() view returns(bytes32)
func (_TaskManagerContract *TaskManagerContractCaller) ADMINROLE(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _TaskManagerContract.contract.Call(opts, &out, "ADMIN_ROLE")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// ADMINROLE is a free data retrieval call binding the contract method 0x75b238fc.
//
// Solidity: function ADMIN_ROLE() view returns(bytes32)
func (_TaskManagerContract *TaskManagerContractSession) ADMINROLE() ([32]byte, error) {
	return _TaskManagerContract.Contract.ADMINROLE(&_TaskManagerContract.CallOpts)
}

// ADMINROLE is a free data retrieval call binding the contract method 0x75b238fc.
//
// Solidity: function ADMIN_ROLE() view returns(bytes32)
func (_TaskManagerContract *TaskManagerContractCallerSession) ADMINROLE() ([32]byte, error) {
	return _TaskManagerContract.Contract.ADMINROLE(&_TaskManagerContract.CallOpts)
}

// DEFAULTADMINROLE is a free data retrieval call binding the contract method 0xa217fddf.
//
// Solidity: function DEFAULT_ADMIN_ROLE() view returns(bytes32)
func (_TaskManagerContract *TaskManagerContractCaller) DEFAULTADMINROLE(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _TaskManagerContract.contract.Call(opts, &out, "DEFAULT_ADMIN_ROLE")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// DEFAULTADMINROLE is a free data retrieval call binding the contract method 0xa217fddf.
//
// Solidity: function DEFAULT_ADMIN_ROLE() view returns(bytes32)
func (_TaskManagerContract *TaskManagerContractSession) DEFAULTADMINROLE() ([32]byte, error) {
	return _TaskManagerContract.Contract.DEFAULTADMINROLE(&_TaskManagerContract.CallOpts)
}

// DEFAULTADMINROLE is a free data retrieval call binding the contract method 0xa217fddf.
//
// Solidity: function DEFAULT_ADMIN_ROLE() view returns(bytes32)
func (_TaskManagerContract *TaskManagerContractCallerSession) DEFAULTADMINROLE() ([32]byte, error) {
	return _TaskManagerContract.Contract.DEFAULTADMINROLE(&_TaskManagerContract.CallOpts)
}

// RELAYERROLE is a free data retrieval call binding the contract method 0x926d7d7f.
//
// Solidity: function RELAYER_ROLE() view returns(bytes32)
func (_TaskManagerContract *TaskManagerContractCaller) RELAYERROLE(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _TaskManagerContract.contract.Call(opts, &out, "RELAYER_ROLE")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// RELAYERROLE is a free data retrieval call binding the contract method 0x926d7d7f.
//
// Solidity: function RELAYER_ROLE() view returns(bytes32)
func (_TaskManagerContract *TaskManagerContractSession) RELAYERROLE() ([32]byte, error) {
	return _TaskManagerContract.Contract.RELAYERROLE(&_TaskManagerContract.CallOpts)
}

// RELAYERROLE is a free data retrieval call binding the contract method 0x926d7d7f.
//
// Solidity: function RELAYER_ROLE() view returns(bytes32)
func (_TaskManagerContract *TaskManagerContractCallerSession) RELAYERROLE() ([32]byte, error) {
	return _TaskManagerContract.Contract.RELAYERROLE(&_TaskManagerContract.CallOpts)
}

// Bitcoin is a free data retrieval call binding the contract method 0xced35070.
//
// Solidity: function bitcoin() view returns(address)
func (_TaskManagerContract *TaskManagerContractCaller) Bitcoin(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _TaskManagerContract.contract.Call(opts, &out, "bitcoin")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Bitcoin is a free data retrieval call binding the contract method 0xced35070.
//
// Solidity: function bitcoin() view returns(address)
func (_TaskManagerContract *TaskManagerContractSession) Bitcoin() (common.Address, error) {
	return _TaskManagerContract.Contract.Bitcoin(&_TaskManagerContract.CallOpts)
}

// Bitcoin is a free data retrieval call binding the contract method 0xced35070.
//
// Solidity: function bitcoin() view returns(address)
func (_TaskManagerContract *TaskManagerContractCallerSession) Bitcoin() (common.Address, error) {
	return _TaskManagerContract.Contract.Bitcoin(&_TaskManagerContract.CallOpts)
}

// Bridge is a free data retrieval call binding the contract method 0xe78cea92.
//
// Solidity: function bridge() view returns(address)
func (_TaskManagerContract *TaskManagerContractCaller) Bridge(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _TaskManagerContract.contract.Call(opts, &out, "bridge")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Bridge is a free data retrieval call binding the contract method 0xe78cea92.
//
// Solidity: function bridge() view returns(address)
func (_TaskManagerContract *TaskManagerContractSession) Bridge() (common.Address, error) {
	return _TaskManagerContract.Contract.Bridge(&_TaskManagerContract.CallOpts)
}

// Bridge is a free data retrieval call binding the contract method 0xe78cea92.
//
// Solidity: function bridge() view returns(address)
func (_TaskManagerContract *TaskManagerContractCallerSession) Bridge() (common.Address, error) {
	return _TaskManagerContract.Contract.Bridge(&_TaskManagerContract.CallOpts)
}

// GetPartnerTasks is a free data retrieval call binding the contract method 0x377a00c0.
//
// Solidity: function getPartnerTasks(uint256 _partnerId) view returns(uint256[])
func (_TaskManagerContract *TaskManagerContractCaller) GetPartnerTasks(opts *bind.CallOpts, _partnerId *big.Int) ([]*big.Int, error) {
	var out []interface{}
	err := _TaskManagerContract.contract.Call(opts, &out, "getPartnerTasks", _partnerId)

	if err != nil {
		return *new([]*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new([]*big.Int)).(*[]*big.Int)

	return out0, err

}

// GetPartnerTasks is a free data retrieval call binding the contract method 0x377a00c0.
//
// Solidity: function getPartnerTasks(uint256 _partnerId) view returns(uint256[])
func (_TaskManagerContract *TaskManagerContractSession) GetPartnerTasks(_partnerId *big.Int) ([]*big.Int, error) {
	return _TaskManagerContract.Contract.GetPartnerTasks(&_TaskManagerContract.CallOpts, _partnerId)
}

// GetPartnerTasks is a free data retrieval call binding the contract method 0x377a00c0.
//
// Solidity: function getPartnerTasks(uint256 _partnerId) view returns(uint256[])
func (_TaskManagerContract *TaskManagerContractCallerSession) GetPartnerTasks(_partnerId *big.Int) ([]*big.Int, error) {
	return _TaskManagerContract.Contract.GetPartnerTasks(&_TaskManagerContract.CallOpts, _partnerId)
}

// GetRoleAdmin is a free data retrieval call binding the contract method 0x248a9ca3.
//
// Solidity: function getRoleAdmin(bytes32 role) view returns(bytes32)
func (_TaskManagerContract *TaskManagerContractCaller) GetRoleAdmin(opts *bind.CallOpts, role [32]byte) ([32]byte, error) {
	var out []interface{}
	err := _TaskManagerContract.contract.Call(opts, &out, "getRoleAdmin", role)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// GetRoleAdmin is a free data retrieval call binding the contract method 0x248a9ca3.
//
// Solidity: function getRoleAdmin(bytes32 role) view returns(bytes32)
func (_TaskManagerContract *TaskManagerContractSession) GetRoleAdmin(role [32]byte) ([32]byte, error) {
	return _TaskManagerContract.Contract.GetRoleAdmin(&_TaskManagerContract.CallOpts, role)
}

// GetRoleAdmin is a free data retrieval call binding the contract method 0x248a9ca3.
//
// Solidity: function getRoleAdmin(bytes32 role) view returns(bytes32)
func (_TaskManagerContract *TaskManagerContractCallerSession) GetRoleAdmin(role [32]byte) ([32]byte, error) {
	return _TaskManagerContract.Contract.GetRoleAdmin(&_TaskManagerContract.CallOpts, role)
}

// GetTask is a free data retrieval call binding the contract method 0x1d65e77e.
//
// Solidity: function getTask(uint256 _index) view returns((uint256,address,uint8,uint32,uint32,uint128,uint32,uint32,bytes32,bytes32,bytes32[7],bytes32[2],bytes32[2]))
func (_TaskManagerContract *TaskManagerContractCaller) GetTask(opts *bind.CallOpts, _index *big.Int) (TaskManagerUpgradeableTask, error) {
	var out []interface{}
	err := _TaskManagerContract.contract.Call(opts, &out, "getTask", _index)

	if err != nil {
		return *new(TaskManagerUpgradeableTask), err
	}

	out0 := *abi.ConvertType(out[0], new(TaskManagerUpgradeableTask)).(*TaskManagerUpgradeableTask)

	return out0, err

}

// GetTask is a free data retrieval call binding the contract method 0x1d65e77e.
//
// Solidity: function getTask(uint256 _index) view returns((uint256,address,uint8,uint32,uint32,uint128,uint32,uint32,bytes32,bytes32,bytes32[7],bytes32[2],bytes32[2]))
func (_TaskManagerContract *TaskManagerContractSession) GetTask(_index *big.Int) (TaskManagerUpgradeableTask, error) {
	return _TaskManagerContract.Contract.GetTask(&_TaskManagerContract.CallOpts, _index)
}

// GetTask is a free data retrieval call binding the contract method 0x1d65e77e.
//
// Solidity: function getTask(uint256 _index) view returns((uint256,address,uint8,uint32,uint32,uint128,uint32,uint32,bytes32,bytes32,bytes32[7],bytes32[2],bytes32[2]))
func (_TaskManagerContract *TaskManagerContractCallerSession) GetTask(_index *big.Int) (TaskManagerUpgradeableTask, error) {
	return _TaskManagerContract.Contract.GetTask(&_TaskManagerContract.CallOpts, _index)
}

// HasPendingTask is a free data retrieval call binding the contract method 0xf34b1e56.
//
// Solidity: function hasPendingTask(address depositAddress) view returns(uint256)
func (_TaskManagerContract *TaskManagerContractCaller) HasPendingTask(opts *bind.CallOpts, depositAddress common.Address) (*big.Int, error) {
	var out []interface{}
	err := _TaskManagerContract.contract.Call(opts, &out, "hasPendingTask", depositAddress)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// HasPendingTask is a free data retrieval call binding the contract method 0xf34b1e56.
//
// Solidity: function hasPendingTask(address depositAddress) view returns(uint256)
func (_TaskManagerContract *TaskManagerContractSession) HasPendingTask(depositAddress common.Address) (*big.Int, error) {
	return _TaskManagerContract.Contract.HasPendingTask(&_TaskManagerContract.CallOpts, depositAddress)
}

// HasPendingTask is a free data retrieval call binding the contract method 0xf34b1e56.
//
// Solidity: function hasPendingTask(address depositAddress) view returns(uint256)
func (_TaskManagerContract *TaskManagerContractCallerSession) HasPendingTask(depositAddress common.Address) (*big.Int, error) {
	return _TaskManagerContract.Contract.HasPendingTask(&_TaskManagerContract.CallOpts, depositAddress)
}

// HasRole is a free data retrieval call binding the contract method 0x91d14854.
//
// Solidity: function hasRole(bytes32 role, address account) view returns(bool)
func (_TaskManagerContract *TaskManagerContractCaller) HasRole(opts *bind.CallOpts, role [32]byte, account common.Address) (bool, error) {
	var out []interface{}
	err := _TaskManagerContract.contract.Call(opts, &out, "hasRole", role, account)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// HasRole is a free data retrieval call binding the contract method 0x91d14854.
//
// Solidity: function hasRole(bytes32 role, address account) view returns(bool)
func (_TaskManagerContract *TaskManagerContractSession) HasRole(role [32]byte, account common.Address) (bool, error) {
	return _TaskManagerContract.Contract.HasRole(&_TaskManagerContract.CallOpts, role, account)
}

// HasRole is a free data retrieval call binding the contract method 0x91d14854.
//
// Solidity: function hasRole(bytes32 role, address account) view returns(bool)
func (_TaskManagerContract *TaskManagerContractCallerSession) HasRole(role [32]byte, account common.Address) (bool, error) {
	return _TaskManagerContract.Contract.HasRole(&_TaskManagerContract.CallOpts, role, account)
}

// PartnerBeacon is a free data retrieval call binding the contract method 0xa5f150e9.
//
// Solidity: function partnerBeacon() view returns(address)
func (_TaskManagerContract *TaskManagerContractCaller) PartnerBeacon(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _TaskManagerContract.contract.Call(opts, &out, "partnerBeacon")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// PartnerBeacon is a free data retrieval call binding the contract method 0xa5f150e9.
//
// Solidity: function partnerBeacon() view returns(address)
func (_TaskManagerContract *TaskManagerContractSession) PartnerBeacon() (common.Address, error) {
	return _TaskManagerContract.Contract.PartnerBeacon(&_TaskManagerContract.CallOpts)
}

// PartnerBeacon is a free data retrieval call binding the contract method 0xa5f150e9.
//
// Solidity: function partnerBeacon() view returns(address)
func (_TaskManagerContract *TaskManagerContractCallerSession) PartnerBeacon() (common.Address, error) {
	return _TaskManagerContract.Contract.PartnerBeacon(&_TaskManagerContract.CallOpts)
}

// PartnerTasks is a free data retrieval call binding the contract method 0xede89484.
//
// Solidity: function partnerTasks(uint256 partnerId, uint256 ) view returns(uint256)
func (_TaskManagerContract *TaskManagerContractCaller) PartnerTasks(opts *bind.CallOpts, partnerId *big.Int, arg1 *big.Int) (*big.Int, error) {
	var out []interface{}
	err := _TaskManagerContract.contract.Call(opts, &out, "partnerTasks", partnerId, arg1)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// PartnerTasks is a free data retrieval call binding the contract method 0xede89484.
//
// Solidity: function partnerTasks(uint256 partnerId, uint256 ) view returns(uint256)
func (_TaskManagerContract *TaskManagerContractSession) PartnerTasks(partnerId *big.Int, arg1 *big.Int) (*big.Int, error) {
	return _TaskManagerContract.Contract.PartnerTasks(&_TaskManagerContract.CallOpts, partnerId, arg1)
}

// PartnerTasks is a free data retrieval call binding the contract method 0xede89484.
//
// Solidity: function partnerTasks(uint256 partnerId, uint256 ) view returns(uint256)
func (_TaskManagerContract *TaskManagerContractCallerSession) PartnerTasks(partnerId *big.Int, arg1 *big.Int) (*big.Int, error) {
	return _TaskManagerContract.Contract.PartnerTasks(&_TaskManagerContract.CallOpts, partnerId, arg1)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_TaskManagerContract *TaskManagerContractCaller) SupportsInterface(opts *bind.CallOpts, interfaceId [4]byte) (bool, error) {
	var out []interface{}
	err := _TaskManagerContract.contract.Call(opts, &out, "supportsInterface", interfaceId)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_TaskManagerContract *TaskManagerContractSession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _TaskManagerContract.Contract.SupportsInterface(&_TaskManagerContract.CallOpts, interfaceId)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_TaskManagerContract *TaskManagerContractCallerSession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _TaskManagerContract.Contract.SupportsInterface(&_TaskManagerContract.CallOpts, interfaceId)
}

// Tasks is a free data retrieval call binding the contract method 0x8d977672.
//
// Solidity: function tasks(uint256 ) view returns(uint256 partnerId, address depositAddress, uint8 state, uint32 timelockEndTime, uint32 deadline, uint128 amount, uint32 fundingTxOut, uint32 timelockTxOut, bytes32 fundingTxHash, bytes32 timelockTxHash)
func (_TaskManagerContract *TaskManagerContractCaller) Tasks(opts *bind.CallOpts, arg0 *big.Int) (struct {
	PartnerId       *big.Int
	DepositAddress  common.Address
	State           uint8
	TimelockEndTime uint32
	Deadline        uint32
	Amount          *big.Int
	FundingTxOut    uint32
	TimelockTxOut   uint32
	FundingTxHash   [32]byte
	TimelockTxHash  [32]byte
}, error) {
	var out []interface{}
	err := _TaskManagerContract.contract.Call(opts, &out, "tasks", arg0)

	outstruct := new(struct {
		PartnerId       *big.Int
		DepositAddress  common.Address
		State           uint8
		TimelockEndTime uint32
		Deadline        uint32
		Amount          *big.Int
		FundingTxOut    uint32
		TimelockTxOut   uint32
		FundingTxHash   [32]byte
		TimelockTxHash  [32]byte
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.PartnerId = *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)
	outstruct.DepositAddress = *abi.ConvertType(out[1], new(common.Address)).(*common.Address)
	outstruct.State = *abi.ConvertType(out[2], new(uint8)).(*uint8)
	outstruct.TimelockEndTime = *abi.ConvertType(out[3], new(uint32)).(*uint32)
	outstruct.Deadline = *abi.ConvertType(out[4], new(uint32)).(*uint32)
	outstruct.Amount = *abi.ConvertType(out[5], new(*big.Int)).(**big.Int)
	outstruct.FundingTxOut = *abi.ConvertType(out[6], new(uint32)).(*uint32)
	outstruct.TimelockTxOut = *abi.ConvertType(out[7], new(uint32)).(*uint32)
	outstruct.FundingTxHash = *abi.ConvertType(out[8], new([32]byte)).(*[32]byte)
	outstruct.TimelockTxHash = *abi.ConvertType(out[9], new([32]byte)).(*[32]byte)

	return *outstruct, err

}

// Tasks is a free data retrieval call binding the contract method 0x8d977672.
//
// Solidity: function tasks(uint256 ) view returns(uint256 partnerId, address depositAddress, uint8 state, uint32 timelockEndTime, uint32 deadline, uint128 amount, uint32 fundingTxOut, uint32 timelockTxOut, bytes32 fundingTxHash, bytes32 timelockTxHash)
func (_TaskManagerContract *TaskManagerContractSession) Tasks(arg0 *big.Int) (struct {
	PartnerId       *big.Int
	DepositAddress  common.Address
	State           uint8
	TimelockEndTime uint32
	Deadline        uint32
	Amount          *big.Int
	FundingTxOut    uint32
	TimelockTxOut   uint32
	FundingTxHash   [32]byte
	TimelockTxHash  [32]byte
}, error) {
	return _TaskManagerContract.Contract.Tasks(&_TaskManagerContract.CallOpts, arg0)
}

// Tasks is a free data retrieval call binding the contract method 0x8d977672.
//
// Solidity: function tasks(uint256 ) view returns(uint256 partnerId, address depositAddress, uint8 state, uint32 timelockEndTime, uint32 deadline, uint128 amount, uint32 fundingTxOut, uint32 timelockTxOut, bytes32 fundingTxHash, bytes32 timelockTxHash)
func (_TaskManagerContract *TaskManagerContractCallerSession) Tasks(arg0 *big.Int) (struct {
	PartnerId       *big.Int
	DepositAddress  common.Address
	State           uint8
	TimelockEndTime uint32
	Deadline        uint32
	Amount          *big.Int
	FundingTxOut    uint32
	TimelockTxOut   uint32
	FundingTxHash   [32]byte
	TimelockTxHash  [32]byte
}, error) {
	return _TaskManagerContract.Contract.Tasks(&_TaskManagerContract.CallOpts, arg0)
}

// VerifyMerkleProof is a free data retrieval call binding the contract method 0x0491323b.
//
// Solidity: function verifyMerkleProof(bytes32 root, bytes32[] proof, bytes32 leaf, uint256 index) pure returns(bool)
func (_TaskManagerContract *TaskManagerContractCaller) VerifyMerkleProof(opts *bind.CallOpts, root [32]byte, proof [][32]byte, leaf [32]byte, index *big.Int) (bool, error) {
	var out []interface{}
	err := _TaskManagerContract.contract.Call(opts, &out, "verifyMerkleProof", root, proof, leaf, index)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// VerifyMerkleProof is a free data retrieval call binding the contract method 0x0491323b.
//
// Solidity: function verifyMerkleProof(bytes32 root, bytes32[] proof, bytes32 leaf, uint256 index) pure returns(bool)
func (_TaskManagerContract *TaskManagerContractSession) VerifyMerkleProof(root [32]byte, proof [][32]byte, leaf [32]byte, index *big.Int) (bool, error) {
	return _TaskManagerContract.Contract.VerifyMerkleProof(&_TaskManagerContract.CallOpts, root, proof, leaf, index)
}

// VerifyMerkleProof is a free data retrieval call binding the contract method 0x0491323b.
//
// Solidity: function verifyMerkleProof(bytes32 root, bytes32[] proof, bytes32 leaf, uint256 index) pure returns(bool)
func (_TaskManagerContract *TaskManagerContractCallerSession) VerifyMerkleProof(root [32]byte, proof [][32]byte, leaf [32]byte, index *big.Int) (bool, error) {
	return _TaskManagerContract.Contract.VerifyMerkleProof(&_TaskManagerContract.CallOpts, root, proof, leaf, index)
}

// Burn is a paid mutator transaction binding the contract method 0x42966c68.
//
// Solidity: function burn(uint256 _taskId) payable returns()
func (_TaskManagerContract *TaskManagerContractTransactor) Burn(opts *bind.TransactOpts, _taskId *big.Int) (*types.Transaction, error) {
	return _TaskManagerContract.contract.Transact(opts, "burn", _taskId)
}

// Burn is a paid mutator transaction binding the contract method 0x42966c68.
//
// Solidity: function burn(uint256 _taskId) payable returns()
func (_TaskManagerContract *TaskManagerContractSession) Burn(_taskId *big.Int) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.Burn(&_TaskManagerContract.TransactOpts, _taskId)
}

// Burn is a paid mutator transaction binding the contract method 0x42966c68.
//
// Solidity: function burn(uint256 _taskId) payable returns()
func (_TaskManagerContract *TaskManagerContractTransactorSession) Burn(_taskId *big.Int) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.Burn(&_TaskManagerContract.TransactOpts, _taskId)
}

// CancelTask is a paid mutator transaction binding the contract method 0x7eec20a8.
//
// Solidity: function cancelTask(uint256 _taskId) returns()
func (_TaskManagerContract *TaskManagerContractTransactor) CancelTask(opts *bind.TransactOpts, _taskId *big.Int) (*types.Transaction, error) {
	return _TaskManagerContract.contract.Transact(opts, "cancelTask", _taskId)
}

// CancelTask is a paid mutator transaction binding the contract method 0x7eec20a8.
//
// Solidity: function cancelTask(uint256 _taskId) returns()
func (_TaskManagerContract *TaskManagerContractSession) CancelTask(_taskId *big.Int) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.CancelTask(&_TaskManagerContract.TransactOpts, _taskId)
}

// CancelTask is a paid mutator transaction binding the contract method 0x7eec20a8.
//
// Solidity: function cancelTask(uint256 _taskId) returns()
func (_TaskManagerContract *TaskManagerContractTransactorSession) CancelTask(_taskId *big.Int) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.CancelTask(&_TaskManagerContract.TransactOpts, _taskId)
}

// ForceBurn is a paid mutator transaction binding the contract method 0x31c10da3.
//
// Solidity: function forceBurn(uint256 _taskId) payable returns()
func (_TaskManagerContract *TaskManagerContractTransactor) ForceBurn(opts *bind.TransactOpts, _taskId *big.Int) (*types.Transaction, error) {
	return _TaskManagerContract.contract.Transact(opts, "forceBurn", _taskId)
}

// ForceBurn is a paid mutator transaction binding the contract method 0x31c10da3.
//
// Solidity: function forceBurn(uint256 _taskId) payable returns()
func (_TaskManagerContract *TaskManagerContractSession) ForceBurn(_taskId *big.Int) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.ForceBurn(&_TaskManagerContract.TransactOpts, _taskId)
}

// ForceBurn is a paid mutator transaction binding the contract method 0x31c10da3.
//
// Solidity: function forceBurn(uint256 _taskId) payable returns()
func (_TaskManagerContract *TaskManagerContractTransactorSession) ForceBurn(_taskId *big.Int) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.ForceBurn(&_TaskManagerContract.TransactOpts, _taskId)
}

// GrantRole is a paid mutator transaction binding the contract method 0x2f2ff15d.
//
// Solidity: function grantRole(bytes32 role, address account) returns()
func (_TaskManagerContract *TaskManagerContractTransactor) GrantRole(opts *bind.TransactOpts, role [32]byte, account common.Address) (*types.Transaction, error) {
	return _TaskManagerContract.contract.Transact(opts, "grantRole", role, account)
}

// GrantRole is a paid mutator transaction binding the contract method 0x2f2ff15d.
//
// Solidity: function grantRole(bytes32 role, address account) returns()
func (_TaskManagerContract *TaskManagerContractSession) GrantRole(role [32]byte, account common.Address) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.GrantRole(&_TaskManagerContract.TransactOpts, role, account)
}

// GrantRole is a paid mutator transaction binding the contract method 0x2f2ff15d.
//
// Solidity: function grantRole(bytes32 role, address account) returns()
func (_TaskManagerContract *TaskManagerContractTransactorSession) GrantRole(role [32]byte, account common.Address) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.GrantRole(&_TaskManagerContract.TransactOpts, role, account)
}

// InitTimelockTx is a paid mutator transaction binding the contract method 0x6db60388.
//
// Solidity: function initTimelockTx(uint256 _taskId, bytes32 _timelockTxHash, uint32 _txOut, bytes32[7] _witnessScript) returns()
func (_TaskManagerContract *TaskManagerContractTransactor) InitTimelockTx(opts *bind.TransactOpts, _taskId *big.Int, _timelockTxHash [32]byte, _txOut uint32, _witnessScript [7][32]byte) (*types.Transaction, error) {
	return _TaskManagerContract.contract.Transact(opts, "initTimelockTx", _taskId, _timelockTxHash, _txOut, _witnessScript)
}

// InitTimelockTx is a paid mutator transaction binding the contract method 0x6db60388.
//
// Solidity: function initTimelockTx(uint256 _taskId, bytes32 _timelockTxHash, uint32 _txOut, bytes32[7] _witnessScript) returns()
func (_TaskManagerContract *TaskManagerContractSession) InitTimelockTx(_taskId *big.Int, _timelockTxHash [32]byte, _txOut uint32, _witnessScript [7][32]byte) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.InitTimelockTx(&_TaskManagerContract.TransactOpts, _taskId, _timelockTxHash, _txOut, _witnessScript)
}

// InitTimelockTx is a paid mutator transaction binding the contract method 0x6db60388.
//
// Solidity: function initTimelockTx(uint256 _taskId, bytes32 _timelockTxHash, uint32 _txOut, bytes32[7] _witnessScript) returns()
func (_TaskManagerContract *TaskManagerContractTransactorSession) InitTimelockTx(_taskId *big.Int, _timelockTxHash [32]byte, _txOut uint32, _witnessScript [7][32]byte) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.InitTimelockTx(&_TaskManagerContract.TransactOpts, _taskId, _timelockTxHash, _txOut, _witnessScript)
}

// Initialize is a paid mutator transaction binding the contract method 0x8129fc1c.
//
// Solidity: function initialize() returns()
func (_TaskManagerContract *TaskManagerContractTransactor) Initialize(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _TaskManagerContract.contract.Transact(opts, "initialize")
}

// Initialize is a paid mutator transaction binding the contract method 0x8129fc1c.
//
// Solidity: function initialize() returns()
func (_TaskManagerContract *TaskManagerContractSession) Initialize() (*types.Transaction, error) {
	return _TaskManagerContract.Contract.Initialize(&_TaskManagerContract.TransactOpts)
}

// Initialize is a paid mutator transaction binding the contract method 0x8129fc1c.
//
// Solidity: function initialize() returns()
func (_TaskManagerContract *TaskManagerContractTransactorSession) Initialize() (*types.Transaction, error) {
	return _TaskManagerContract.Contract.Initialize(&_TaskManagerContract.TransactOpts)
}

// ProcessTimelockTx is a paid mutator transaction binding the contract method 0x4c0753bf.
//
// Solidity: function processTimelockTx(uint256 _taskId, uint256 height, bytes32[] proof, uint256 _index) returns()
func (_TaskManagerContract *TaskManagerContractTransactor) ProcessTimelockTx(opts *bind.TransactOpts, _taskId *big.Int, height *big.Int, proof [][32]byte, _index *big.Int) (*types.Transaction, error) {
	return _TaskManagerContract.contract.Transact(opts, "processTimelockTx", _taskId, height, proof, _index)
}

// ProcessTimelockTx is a paid mutator transaction binding the contract method 0x4c0753bf.
//
// Solidity: function processTimelockTx(uint256 _taskId, uint256 height, bytes32[] proof, uint256 _index) returns()
func (_TaskManagerContract *TaskManagerContractSession) ProcessTimelockTx(_taskId *big.Int, height *big.Int, proof [][32]byte, _index *big.Int) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.ProcessTimelockTx(&_TaskManagerContract.TransactOpts, _taskId, height, proof, _index)
}

// ProcessTimelockTx is a paid mutator transaction binding the contract method 0x4c0753bf.
//
// Solidity: function processTimelockTx(uint256 _taskId, uint256 height, bytes32[] proof, uint256 _index) returns()
func (_TaskManagerContract *TaskManagerContractTransactorSession) ProcessTimelockTx(_taskId *big.Int, height *big.Int, proof [][32]byte, _index *big.Int) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.ProcessTimelockTx(&_TaskManagerContract.TransactOpts, _taskId, height, proof, _index)
}

// ReceiveFunds is a paid mutator transaction binding the contract method 0x0ae07b54.
//
// Solidity: function receiveFunds(uint256 _taskId, uint128 _amount, bytes32 _fundingTxHash, uint32 _txOut) returns()
func (_TaskManagerContract *TaskManagerContractTransactor) ReceiveFunds(opts *bind.TransactOpts, _taskId *big.Int, _amount *big.Int, _fundingTxHash [32]byte, _txOut uint32) (*types.Transaction, error) {
	return _TaskManagerContract.contract.Transact(opts, "receiveFunds", _taskId, _amount, _fundingTxHash, _txOut)
}

// ReceiveFunds is a paid mutator transaction binding the contract method 0x0ae07b54.
//
// Solidity: function receiveFunds(uint256 _taskId, uint128 _amount, bytes32 _fundingTxHash, uint32 _txOut) returns()
func (_TaskManagerContract *TaskManagerContractSession) ReceiveFunds(_taskId *big.Int, _amount *big.Int, _fundingTxHash [32]byte, _txOut uint32) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.ReceiveFunds(&_TaskManagerContract.TransactOpts, _taskId, _amount, _fundingTxHash, _txOut)
}

// ReceiveFunds is a paid mutator transaction binding the contract method 0x0ae07b54.
//
// Solidity: function receiveFunds(uint256 _taskId, uint128 _amount, bytes32 _fundingTxHash, uint32 _txOut) returns()
func (_TaskManagerContract *TaskManagerContractTransactorSession) ReceiveFunds(_taskId *big.Int, _amount *big.Int, _fundingTxHash [32]byte, _txOut uint32) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.ReceiveFunds(&_TaskManagerContract.TransactOpts, _taskId, _amount, _fundingTxHash, _txOut)
}

// RenounceRole is a paid mutator transaction binding the contract method 0x36568abe.
//
// Solidity: function renounceRole(bytes32 role, address callerConfirmation) returns()
func (_TaskManagerContract *TaskManagerContractTransactor) RenounceRole(opts *bind.TransactOpts, role [32]byte, callerConfirmation common.Address) (*types.Transaction, error) {
	return _TaskManagerContract.contract.Transact(opts, "renounceRole", role, callerConfirmation)
}

// RenounceRole is a paid mutator transaction binding the contract method 0x36568abe.
//
// Solidity: function renounceRole(bytes32 role, address callerConfirmation) returns()
func (_TaskManagerContract *TaskManagerContractSession) RenounceRole(role [32]byte, callerConfirmation common.Address) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.RenounceRole(&_TaskManagerContract.TransactOpts, role, callerConfirmation)
}

// RenounceRole is a paid mutator transaction binding the contract method 0x36568abe.
//
// Solidity: function renounceRole(bytes32 role, address callerConfirmation) returns()
func (_TaskManagerContract *TaskManagerContractTransactorSession) RenounceRole(role [32]byte, callerConfirmation common.Address) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.RenounceRole(&_TaskManagerContract.TransactOpts, role, callerConfirmation)
}

// RevokeRole is a paid mutator transaction binding the contract method 0xd547741f.
//
// Solidity: function revokeRole(bytes32 role, address account) returns()
func (_TaskManagerContract *TaskManagerContractTransactor) RevokeRole(opts *bind.TransactOpts, role [32]byte, account common.Address) (*types.Transaction, error) {
	return _TaskManagerContract.contract.Transact(opts, "revokeRole", role, account)
}

// RevokeRole is a paid mutator transaction binding the contract method 0xd547741f.
//
// Solidity: function revokeRole(bytes32 role, address account) returns()
func (_TaskManagerContract *TaskManagerContractSession) RevokeRole(role [32]byte, account common.Address) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.RevokeRole(&_TaskManagerContract.TransactOpts, role, account)
}

// RevokeRole is a paid mutator transaction binding the contract method 0xd547741f.
//
// Solidity: function revokeRole(bytes32 role, address account) returns()
func (_TaskManagerContract *TaskManagerContractTransactorSession) RevokeRole(role [32]byte, account common.Address) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.RevokeRole(&_TaskManagerContract.TransactOpts, role, account)
}

// SetupTask is a paid mutator transaction binding the contract method 0xd0c97a14.
//
// Solidity: function setupTask(uint256 _partnerId, address _depositAddress, uint32 _timelockEndTime, uint32 _deadline, uint128 _amount, bytes32[2] _btcAddress, bytes32[2] _btcPubKey) returns()
func (_TaskManagerContract *TaskManagerContractTransactor) SetupTask(opts *bind.TransactOpts, _partnerId *big.Int, _depositAddress common.Address, _timelockEndTime uint32, _deadline uint32, _amount *big.Int, _btcAddress [2][32]byte, _btcPubKey [2][32]byte) (*types.Transaction, error) {
	return _TaskManagerContract.contract.Transact(opts, "setupTask", _partnerId, _depositAddress, _timelockEndTime, _deadline, _amount, _btcAddress, _btcPubKey)
}

// SetupTask is a paid mutator transaction binding the contract method 0xd0c97a14.
//
// Solidity: function setupTask(uint256 _partnerId, address _depositAddress, uint32 _timelockEndTime, uint32 _deadline, uint128 _amount, bytes32[2] _btcAddress, bytes32[2] _btcPubKey) returns()
func (_TaskManagerContract *TaskManagerContractSession) SetupTask(_partnerId *big.Int, _depositAddress common.Address, _timelockEndTime uint32, _deadline uint32, _amount *big.Int, _btcAddress [2][32]byte, _btcPubKey [2][32]byte) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.SetupTask(&_TaskManagerContract.TransactOpts, _partnerId, _depositAddress, _timelockEndTime, _deadline, _amount, _btcAddress, _btcPubKey)
}

// SetupTask is a paid mutator transaction binding the contract method 0xd0c97a14.
//
// Solidity: function setupTask(uint256 _partnerId, address _depositAddress, uint32 _timelockEndTime, uint32 _deadline, uint128 _amount, bytes32[2] _btcAddress, bytes32[2] _btcPubKey) returns()
func (_TaskManagerContract *TaskManagerContractTransactorSession) SetupTask(_partnerId *big.Int, _depositAddress common.Address, _timelockEndTime uint32, _deadline uint32, _amount *big.Int, _btcAddress [2][32]byte, _btcPubKey [2][32]byte) (*types.Transaction, error) {
	return _TaskManagerContract.Contract.SetupTask(&_TaskManagerContract.TransactOpts, _partnerId, _depositAddress, _timelockEndTime, _deadline, _amount, _btcAddress, _btcPubKey)
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_TaskManagerContract *TaskManagerContractTransactor) Receive(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _TaskManagerContract.contract.RawTransact(opts, nil) // calldata is disallowed for receive function
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_TaskManagerContract *TaskManagerContractSession) Receive() (*types.Transaction, error) {
	return _TaskManagerContract.Contract.Receive(&_TaskManagerContract.TransactOpts)
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_TaskManagerContract *TaskManagerContractTransactorSession) Receive() (*types.Transaction, error) {
	return _TaskManagerContract.Contract.Receive(&_TaskManagerContract.TransactOpts)
}

// TaskManagerContractBurnedIterator is returned from FilterBurned and is used to iterate over the raw logs and unpacked data for Burned events raised by the TaskManagerContract contract.
type TaskManagerContractBurnedIterator struct {
	Event *TaskManagerContractBurned // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *TaskManagerContractBurnedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(TaskManagerContractBurned)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(TaskManagerContractBurned)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *TaskManagerContractBurnedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *TaskManagerContractBurnedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// TaskManagerContractBurned represents a Burned event raised by the TaskManagerContract contract.
type TaskManagerContractBurned struct {
	TaskId *big.Int
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterBurned is a free log retrieval operation binding the contract event 0xd83c63197e8e676d80ab0122beba9a9d20f3828839e9a1d6fe81d242e9cd7e6e.
//
// Solidity: event Burned(uint256 taskId)
func (_TaskManagerContract *TaskManagerContractFilterer) FilterBurned(opts *bind.FilterOpts) (*TaskManagerContractBurnedIterator, error) {

	logs, sub, err := _TaskManagerContract.contract.FilterLogs(opts, "Burned")
	if err != nil {
		return nil, err
	}
	return &TaskManagerContractBurnedIterator{contract: _TaskManagerContract.contract, event: "Burned", logs: logs, sub: sub}, nil
}

// WatchBurned is a free log subscription operation binding the contract event 0xd83c63197e8e676d80ab0122beba9a9d20f3828839e9a1d6fe81d242e9cd7e6e.
//
// Solidity: event Burned(uint256 taskId)
func (_TaskManagerContract *TaskManagerContractFilterer) WatchBurned(opts *bind.WatchOpts, sink chan<- *TaskManagerContractBurned) (event.Subscription, error) {

	logs, sub, err := _TaskManagerContract.contract.WatchLogs(opts, "Burned")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(TaskManagerContractBurned)
				if err := _TaskManagerContract.contract.UnpackLog(event, "Burned", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseBurned is a log parse operation binding the contract event 0xd83c63197e8e676d80ab0122beba9a9d20f3828839e9a1d6fe81d242e9cd7e6e.
//
// Solidity: event Burned(uint256 taskId)
func (_TaskManagerContract *TaskManagerContractFilterer) ParseBurned(log types.Log) (*TaskManagerContractBurned, error) {
	event := new(TaskManagerContractBurned)
	if err := _TaskManagerContract.contract.UnpackLog(event, "Burned", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// TaskManagerContractFundsReceivedIterator is returned from FilterFundsReceived and is used to iterate over the raw logs and unpacked data for FundsReceived events raised by the TaskManagerContract contract.
type TaskManagerContractFundsReceivedIterator struct {
	Event *TaskManagerContractFundsReceived // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *TaskManagerContractFundsReceivedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(TaskManagerContractFundsReceived)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(TaskManagerContractFundsReceived)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *TaskManagerContractFundsReceivedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *TaskManagerContractFundsReceivedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// TaskManagerContractFundsReceived represents a FundsReceived event raised by the TaskManagerContract contract.
type TaskManagerContractFundsReceived struct {
	TaskId        *big.Int
	FundingTxHash [32]byte
	TxOut         uint32
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterFundsReceived is a free log retrieval operation binding the contract event 0x6a5e8552bdc593fdffaf48e4035ee6c81433110d2c15809037dc72e130dcba7d.
//
// Solidity: event FundsReceived(uint256 taskId, bytes32 fundingTxHash, uint32 txOut)
func (_TaskManagerContract *TaskManagerContractFilterer) FilterFundsReceived(opts *bind.FilterOpts) (*TaskManagerContractFundsReceivedIterator, error) {

	logs, sub, err := _TaskManagerContract.contract.FilterLogs(opts, "FundsReceived")
	if err != nil {
		return nil, err
	}
	return &TaskManagerContractFundsReceivedIterator{contract: _TaskManagerContract.contract, event: "FundsReceived", logs: logs, sub: sub}, nil
}

// WatchFundsReceived is a free log subscription operation binding the contract event 0x6a5e8552bdc593fdffaf48e4035ee6c81433110d2c15809037dc72e130dcba7d.
//
// Solidity: event FundsReceived(uint256 taskId, bytes32 fundingTxHash, uint32 txOut)
func (_TaskManagerContract *TaskManagerContractFilterer) WatchFundsReceived(opts *bind.WatchOpts, sink chan<- *TaskManagerContractFundsReceived) (event.Subscription, error) {

	logs, sub, err := _TaskManagerContract.contract.WatchLogs(opts, "FundsReceived")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(TaskManagerContractFundsReceived)
				if err := _TaskManagerContract.contract.UnpackLog(event, "FundsReceived", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseFundsReceived is a log parse operation binding the contract event 0x6a5e8552bdc593fdffaf48e4035ee6c81433110d2c15809037dc72e130dcba7d.
//
// Solidity: event FundsReceived(uint256 taskId, bytes32 fundingTxHash, uint32 txOut)
func (_TaskManagerContract *TaskManagerContractFilterer) ParseFundsReceived(log types.Log) (*TaskManagerContractFundsReceived, error) {
	event := new(TaskManagerContractFundsReceived)
	if err := _TaskManagerContract.contract.UnpackLog(event, "FundsReceived", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// TaskManagerContractInitializedIterator is returned from FilterInitialized and is used to iterate over the raw logs and unpacked data for Initialized events raised by the TaskManagerContract contract.
type TaskManagerContractInitializedIterator struct {
	Event *TaskManagerContractInitialized // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *TaskManagerContractInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(TaskManagerContractInitialized)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(TaskManagerContractInitialized)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *TaskManagerContractInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *TaskManagerContractInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// TaskManagerContractInitialized represents a Initialized event raised by the TaskManagerContract contract.
type TaskManagerContractInitialized struct {
	Version uint64
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterInitialized is a free log retrieval operation binding the contract event 0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2.
//
// Solidity: event Initialized(uint64 version)
func (_TaskManagerContract *TaskManagerContractFilterer) FilterInitialized(opts *bind.FilterOpts) (*TaskManagerContractInitializedIterator, error) {

	logs, sub, err := _TaskManagerContract.contract.FilterLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return &TaskManagerContractInitializedIterator{contract: _TaskManagerContract.contract, event: "Initialized", logs: logs, sub: sub}, nil
}

// WatchInitialized is a free log subscription operation binding the contract event 0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2.
//
// Solidity: event Initialized(uint64 version)
func (_TaskManagerContract *TaskManagerContractFilterer) WatchInitialized(opts *bind.WatchOpts, sink chan<- *TaskManagerContractInitialized) (event.Subscription, error) {

	logs, sub, err := _TaskManagerContract.contract.WatchLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(TaskManagerContractInitialized)
				if err := _TaskManagerContract.contract.UnpackLog(event, "Initialized", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseInitialized is a log parse operation binding the contract event 0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2.
//
// Solidity: event Initialized(uint64 version)
func (_TaskManagerContract *TaskManagerContractFilterer) ParseInitialized(log types.Log) (*TaskManagerContractInitialized, error) {
	event := new(TaskManagerContractInitialized)
	if err := _TaskManagerContract.contract.UnpackLog(event, "Initialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// TaskManagerContractRoleAdminChangedIterator is returned from FilterRoleAdminChanged and is used to iterate over the raw logs and unpacked data for RoleAdminChanged events raised by the TaskManagerContract contract.
type TaskManagerContractRoleAdminChangedIterator struct {
	Event *TaskManagerContractRoleAdminChanged // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *TaskManagerContractRoleAdminChangedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(TaskManagerContractRoleAdminChanged)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(TaskManagerContractRoleAdminChanged)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *TaskManagerContractRoleAdminChangedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *TaskManagerContractRoleAdminChangedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// TaskManagerContractRoleAdminChanged represents a RoleAdminChanged event raised by the TaskManagerContract contract.
type TaskManagerContractRoleAdminChanged struct {
	Role              [32]byte
	PreviousAdminRole [32]byte
	NewAdminRole      [32]byte
	Raw               types.Log // Blockchain specific contextual infos
}

// FilterRoleAdminChanged is a free log retrieval operation binding the contract event 0xbd79b86ffe0ab8e8776151514217cd7cacd52c909f66475c3af44e129f0b00ff.
//
// Solidity: event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole)
func (_TaskManagerContract *TaskManagerContractFilterer) FilterRoleAdminChanged(opts *bind.FilterOpts, role [][32]byte, previousAdminRole [][32]byte, newAdminRole [][32]byte) (*TaskManagerContractRoleAdminChangedIterator, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var previousAdminRoleRule []interface{}
	for _, previousAdminRoleItem := range previousAdminRole {
		previousAdminRoleRule = append(previousAdminRoleRule, previousAdminRoleItem)
	}
	var newAdminRoleRule []interface{}
	for _, newAdminRoleItem := range newAdminRole {
		newAdminRoleRule = append(newAdminRoleRule, newAdminRoleItem)
	}

	logs, sub, err := _TaskManagerContract.contract.FilterLogs(opts, "RoleAdminChanged", roleRule, previousAdminRoleRule, newAdminRoleRule)
	if err != nil {
		return nil, err
	}
	return &TaskManagerContractRoleAdminChangedIterator{contract: _TaskManagerContract.contract, event: "RoleAdminChanged", logs: logs, sub: sub}, nil
}

// WatchRoleAdminChanged is a free log subscription operation binding the contract event 0xbd79b86ffe0ab8e8776151514217cd7cacd52c909f66475c3af44e129f0b00ff.
//
// Solidity: event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole)
func (_TaskManagerContract *TaskManagerContractFilterer) WatchRoleAdminChanged(opts *bind.WatchOpts, sink chan<- *TaskManagerContractRoleAdminChanged, role [][32]byte, previousAdminRole [][32]byte, newAdminRole [][32]byte) (event.Subscription, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var previousAdminRoleRule []interface{}
	for _, previousAdminRoleItem := range previousAdminRole {
		previousAdminRoleRule = append(previousAdminRoleRule, previousAdminRoleItem)
	}
	var newAdminRoleRule []interface{}
	for _, newAdminRoleItem := range newAdminRole {
		newAdminRoleRule = append(newAdminRoleRule, newAdminRoleItem)
	}

	logs, sub, err := _TaskManagerContract.contract.WatchLogs(opts, "RoleAdminChanged", roleRule, previousAdminRoleRule, newAdminRoleRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(TaskManagerContractRoleAdminChanged)
				if err := _TaskManagerContract.contract.UnpackLog(event, "RoleAdminChanged", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseRoleAdminChanged is a log parse operation binding the contract event 0xbd79b86ffe0ab8e8776151514217cd7cacd52c909f66475c3af44e129f0b00ff.
//
// Solidity: event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole)
func (_TaskManagerContract *TaskManagerContractFilterer) ParseRoleAdminChanged(log types.Log) (*TaskManagerContractRoleAdminChanged, error) {
	event := new(TaskManagerContractRoleAdminChanged)
	if err := _TaskManagerContract.contract.UnpackLog(event, "RoleAdminChanged", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// TaskManagerContractRoleGrantedIterator is returned from FilterRoleGranted and is used to iterate over the raw logs and unpacked data for RoleGranted events raised by the TaskManagerContract contract.
type TaskManagerContractRoleGrantedIterator struct {
	Event *TaskManagerContractRoleGranted // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *TaskManagerContractRoleGrantedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(TaskManagerContractRoleGranted)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(TaskManagerContractRoleGranted)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *TaskManagerContractRoleGrantedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *TaskManagerContractRoleGrantedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// TaskManagerContractRoleGranted represents a RoleGranted event raised by the TaskManagerContract contract.
type TaskManagerContractRoleGranted struct {
	Role    [32]byte
	Account common.Address
	Sender  common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterRoleGranted is a free log retrieval operation binding the contract event 0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d.
//
// Solidity: event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)
func (_TaskManagerContract *TaskManagerContractFilterer) FilterRoleGranted(opts *bind.FilterOpts, role [][32]byte, account []common.Address, sender []common.Address) (*TaskManagerContractRoleGrantedIterator, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _TaskManagerContract.contract.FilterLogs(opts, "RoleGranted", roleRule, accountRule, senderRule)
	if err != nil {
		return nil, err
	}
	return &TaskManagerContractRoleGrantedIterator{contract: _TaskManagerContract.contract, event: "RoleGranted", logs: logs, sub: sub}, nil
}

// WatchRoleGranted is a free log subscription operation binding the contract event 0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d.
//
// Solidity: event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)
func (_TaskManagerContract *TaskManagerContractFilterer) WatchRoleGranted(opts *bind.WatchOpts, sink chan<- *TaskManagerContractRoleGranted, role [][32]byte, account []common.Address, sender []common.Address) (event.Subscription, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _TaskManagerContract.contract.WatchLogs(opts, "RoleGranted", roleRule, accountRule, senderRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(TaskManagerContractRoleGranted)
				if err := _TaskManagerContract.contract.UnpackLog(event, "RoleGranted", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseRoleGranted is a log parse operation binding the contract event 0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d.
//
// Solidity: event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)
func (_TaskManagerContract *TaskManagerContractFilterer) ParseRoleGranted(log types.Log) (*TaskManagerContractRoleGranted, error) {
	event := new(TaskManagerContractRoleGranted)
	if err := _TaskManagerContract.contract.UnpackLog(event, "RoleGranted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// TaskManagerContractRoleRevokedIterator is returned from FilterRoleRevoked and is used to iterate over the raw logs and unpacked data for RoleRevoked events raised by the TaskManagerContract contract.
type TaskManagerContractRoleRevokedIterator struct {
	Event *TaskManagerContractRoleRevoked // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *TaskManagerContractRoleRevokedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(TaskManagerContractRoleRevoked)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(TaskManagerContractRoleRevoked)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *TaskManagerContractRoleRevokedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *TaskManagerContractRoleRevokedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// TaskManagerContractRoleRevoked represents a RoleRevoked event raised by the TaskManagerContract contract.
type TaskManagerContractRoleRevoked struct {
	Role    [32]byte
	Account common.Address
	Sender  common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterRoleRevoked is a free log retrieval operation binding the contract event 0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b.
//
// Solidity: event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)
func (_TaskManagerContract *TaskManagerContractFilterer) FilterRoleRevoked(opts *bind.FilterOpts, role [][32]byte, account []common.Address, sender []common.Address) (*TaskManagerContractRoleRevokedIterator, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _TaskManagerContract.contract.FilterLogs(opts, "RoleRevoked", roleRule, accountRule, senderRule)
	if err != nil {
		return nil, err
	}
	return &TaskManagerContractRoleRevokedIterator{contract: _TaskManagerContract.contract, event: "RoleRevoked", logs: logs, sub: sub}, nil
}

// WatchRoleRevoked is a free log subscription operation binding the contract event 0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b.
//
// Solidity: event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)
func (_TaskManagerContract *TaskManagerContractFilterer) WatchRoleRevoked(opts *bind.WatchOpts, sink chan<- *TaskManagerContractRoleRevoked, role [][32]byte, account []common.Address, sender []common.Address) (event.Subscription, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _TaskManagerContract.contract.WatchLogs(opts, "RoleRevoked", roleRule, accountRule, senderRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(TaskManagerContractRoleRevoked)
				if err := _TaskManagerContract.contract.UnpackLog(event, "RoleRevoked", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseRoleRevoked is a log parse operation binding the contract event 0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b.
//
// Solidity: event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)
func (_TaskManagerContract *TaskManagerContractFilterer) ParseRoleRevoked(log types.Log) (*TaskManagerContractRoleRevoked, error) {
	event := new(TaskManagerContractRoleRevoked)
	if err := _TaskManagerContract.contract.UnpackLog(event, "RoleRevoked", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// TaskManagerContractTaskCancelledIterator is returned from FilterTaskCancelled and is used to iterate over the raw logs and unpacked data for TaskCancelled events raised by the TaskManagerContract contract.
type TaskManagerContractTaskCancelledIterator struct {
	Event *TaskManagerContractTaskCancelled // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *TaskManagerContractTaskCancelledIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(TaskManagerContractTaskCancelled)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(TaskManagerContractTaskCancelled)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *TaskManagerContractTaskCancelledIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *TaskManagerContractTaskCancelledIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// TaskManagerContractTaskCancelled represents a TaskCancelled event raised by the TaskManagerContract contract.
type TaskManagerContractTaskCancelled struct {
	TaskId *big.Int
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterTaskCancelled is a free log retrieval operation binding the contract event 0xc6eacc3aa5b2aa77b5a826b832a804ca0b71830ec74f9aa57a15edd978c31ed6.
//
// Solidity: event TaskCancelled(uint256 taskId)
func (_TaskManagerContract *TaskManagerContractFilterer) FilterTaskCancelled(opts *bind.FilterOpts) (*TaskManagerContractTaskCancelledIterator, error) {

	logs, sub, err := _TaskManagerContract.contract.FilterLogs(opts, "TaskCancelled")
	if err != nil {
		return nil, err
	}
	return &TaskManagerContractTaskCancelledIterator{contract: _TaskManagerContract.contract, event: "TaskCancelled", logs: logs, sub: sub}, nil
}

// WatchTaskCancelled is a free log subscription operation binding the contract event 0xc6eacc3aa5b2aa77b5a826b832a804ca0b71830ec74f9aa57a15edd978c31ed6.
//
// Solidity: event TaskCancelled(uint256 taskId)
func (_TaskManagerContract *TaskManagerContractFilterer) WatchTaskCancelled(opts *bind.WatchOpts, sink chan<- *TaskManagerContractTaskCancelled) (event.Subscription, error) {

	logs, sub, err := _TaskManagerContract.contract.WatchLogs(opts, "TaskCancelled")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(TaskManagerContractTaskCancelled)
				if err := _TaskManagerContract.contract.UnpackLog(event, "TaskCancelled", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseTaskCancelled is a log parse operation binding the contract event 0xc6eacc3aa5b2aa77b5a826b832a804ca0b71830ec74f9aa57a15edd978c31ed6.
//
// Solidity: event TaskCancelled(uint256 taskId)
func (_TaskManagerContract *TaskManagerContractFilterer) ParseTaskCancelled(log types.Log) (*TaskManagerContractTaskCancelled, error) {
	event := new(TaskManagerContractTaskCancelled)
	if err := _TaskManagerContract.contract.UnpackLog(event, "TaskCancelled", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// TaskManagerContractTaskCreatedIterator is returned from FilterTaskCreated and is used to iterate over the raw logs and unpacked data for TaskCreated events raised by the TaskManagerContract contract.
type TaskManagerContractTaskCreatedIterator struct {
	Event *TaskManagerContractTaskCreated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *TaskManagerContractTaskCreatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(TaskManagerContractTaskCreated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(TaskManagerContractTaskCreated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *TaskManagerContractTaskCreatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *TaskManagerContractTaskCreatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// TaskManagerContractTaskCreated represents a TaskCreated event raised by the TaskManagerContract contract.
type TaskManagerContractTaskCreated struct {
	TaskId *big.Int
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterTaskCreated is a free log retrieval operation binding the contract event 0xba46948ae716559226cede7aac0175e8ddd11b7cb3ea0369c9f218ef908b87d5.
//
// Solidity: event TaskCreated(uint256 taskId)
func (_TaskManagerContract *TaskManagerContractFilterer) FilterTaskCreated(opts *bind.FilterOpts) (*TaskManagerContractTaskCreatedIterator, error) {

	logs, sub, err := _TaskManagerContract.contract.FilterLogs(opts, "TaskCreated")
	if err != nil {
		return nil, err
	}
	return &TaskManagerContractTaskCreatedIterator{contract: _TaskManagerContract.contract, event: "TaskCreated", logs: logs, sub: sub}, nil
}

// WatchTaskCreated is a free log subscription operation binding the contract event 0xba46948ae716559226cede7aac0175e8ddd11b7cb3ea0369c9f218ef908b87d5.
//
// Solidity: event TaskCreated(uint256 taskId)
func (_TaskManagerContract *TaskManagerContractFilterer) WatchTaskCreated(opts *bind.WatchOpts, sink chan<- *TaskManagerContractTaskCreated) (event.Subscription, error) {

	logs, sub, err := _TaskManagerContract.contract.WatchLogs(opts, "TaskCreated")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(TaskManagerContractTaskCreated)
				if err := _TaskManagerContract.contract.UnpackLog(event, "TaskCreated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseTaskCreated is a log parse operation binding the contract event 0xba46948ae716559226cede7aac0175e8ddd11b7cb3ea0369c9f218ef908b87d5.
//
// Solidity: event TaskCreated(uint256 taskId)
func (_TaskManagerContract *TaskManagerContractFilterer) ParseTaskCreated(log types.Log) (*TaskManagerContractTaskCreated, error) {
	event := new(TaskManagerContractTaskCreated)
	if err := _TaskManagerContract.contract.UnpackLog(event, "TaskCreated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// TaskManagerContractTimelockInitializedIterator is returned from FilterTimelockInitialized and is used to iterate over the raw logs and unpacked data for TimelockInitialized events raised by the TaskManagerContract contract.
type TaskManagerContractTimelockInitializedIterator struct {
	Event *TaskManagerContractTimelockInitialized // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *TaskManagerContractTimelockInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(TaskManagerContractTimelockInitialized)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(TaskManagerContractTimelockInitialized)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *TaskManagerContractTimelockInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *TaskManagerContractTimelockInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// TaskManagerContractTimelockInitialized represents a TimelockInitialized event raised by the TaskManagerContract contract.
type TaskManagerContractTimelockInitialized struct {
	TaskId         *big.Int
	TimelockTxHash [32]byte
	TxOut          uint32
	WitnessScript  [7][32]byte
	Raw            types.Log // Blockchain specific contextual infos
}

// FilterTimelockInitialized is a free log retrieval operation binding the contract event 0x282681ea0d915e32775fabcade61d05ff57370dabaef001ec07543fb70bbdfdd.
//
// Solidity: event TimelockInitialized(uint256 taskId, bytes32 timelockTxHash, uint32 txOut, bytes32[7] witnessScript)
func (_TaskManagerContract *TaskManagerContractFilterer) FilterTimelockInitialized(opts *bind.FilterOpts) (*TaskManagerContractTimelockInitializedIterator, error) {

	logs, sub, err := _TaskManagerContract.contract.FilterLogs(opts, "TimelockInitialized")
	if err != nil {
		return nil, err
	}
	return &TaskManagerContractTimelockInitializedIterator{contract: _TaskManagerContract.contract, event: "TimelockInitialized", logs: logs, sub: sub}, nil
}

// WatchTimelockInitialized is a free log subscription operation binding the contract event 0x282681ea0d915e32775fabcade61d05ff57370dabaef001ec07543fb70bbdfdd.
//
// Solidity: event TimelockInitialized(uint256 taskId, bytes32 timelockTxHash, uint32 txOut, bytes32[7] witnessScript)
func (_TaskManagerContract *TaskManagerContractFilterer) WatchTimelockInitialized(opts *bind.WatchOpts, sink chan<- *TaskManagerContractTimelockInitialized) (event.Subscription, error) {

	logs, sub, err := _TaskManagerContract.contract.WatchLogs(opts, "TimelockInitialized")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(TaskManagerContractTimelockInitialized)
				if err := _TaskManagerContract.contract.UnpackLog(event, "TimelockInitialized", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseTimelockInitialized is a log parse operation binding the contract event 0x282681ea0d915e32775fabcade61d05ff57370dabaef001ec07543fb70bbdfdd.
//
// Solidity: event TimelockInitialized(uint256 taskId, bytes32 timelockTxHash, uint32 txOut, bytes32[7] witnessScript)
func (_TaskManagerContract *TaskManagerContractFilterer) ParseTimelockInitialized(log types.Log) (*TaskManagerContractTimelockInitialized, error) {
	event := new(TaskManagerContractTimelockInitialized)
	if err := _TaskManagerContract.contract.UnpackLog(event, "TimelockInitialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// TaskManagerContractTimelockProcessedIterator is returned from FilterTimelockProcessed and is used to iterate over the raw logs and unpacked data for TimelockProcessed events raised by the TaskManagerContract contract.
type TaskManagerContractTimelockProcessedIterator struct {
	Event *TaskManagerContractTimelockProcessed // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *TaskManagerContractTimelockProcessedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(TaskManagerContractTimelockProcessed)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(TaskManagerContractTimelockProcessed)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *TaskManagerContractTimelockProcessedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *TaskManagerContractTimelockProcessedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// TaskManagerContractTimelockProcessed represents a TimelockProcessed event raised by the TaskManagerContract contract.
type TaskManagerContractTimelockProcessed struct {
	TaskId *big.Int
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterTimelockProcessed is a free log retrieval operation binding the contract event 0xecf2ef94d15626de08dc4c22507c16f7be7f21bed8681484d8096491332e55f9.
//
// Solidity: event TimelockProcessed(uint256 taskId)
func (_TaskManagerContract *TaskManagerContractFilterer) FilterTimelockProcessed(opts *bind.FilterOpts) (*TaskManagerContractTimelockProcessedIterator, error) {

	logs, sub, err := _TaskManagerContract.contract.FilterLogs(opts, "TimelockProcessed")
	if err != nil {
		return nil, err
	}
	return &TaskManagerContractTimelockProcessedIterator{contract: _TaskManagerContract.contract, event: "TimelockProcessed", logs: logs, sub: sub}, nil
}

// WatchTimelockProcessed is a free log subscription operation binding the contract event 0xecf2ef94d15626de08dc4c22507c16f7be7f21bed8681484d8096491332e55f9.
//
// Solidity: event TimelockProcessed(uint256 taskId)
func (_TaskManagerContract *TaskManagerContractFilterer) WatchTimelockProcessed(opts *bind.WatchOpts, sink chan<- *TaskManagerContractTimelockProcessed) (event.Subscription, error) {

	logs, sub, err := _TaskManagerContract.contract.WatchLogs(opts, "TimelockProcessed")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(TaskManagerContractTimelockProcessed)
				if err := _TaskManagerContract.contract.UnpackLog(event, "TimelockProcessed", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseTimelockProcessed is a log parse operation binding the contract event 0xecf2ef94d15626de08dc4c22507c16f7be7f21bed8681484d8096491332e55f9.
//
// Solidity: event TimelockProcessed(uint256 taskId)
func (_TaskManagerContract *TaskManagerContractFilterer) ParseTimelockProcessed(log types.Log) (*TaskManagerContractTimelockProcessed, error) {
	event := new(TaskManagerContractTimelockProcessed)
	if err := _TaskManagerContract.contract.UnpackLog(event, "TimelockProcessed", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
