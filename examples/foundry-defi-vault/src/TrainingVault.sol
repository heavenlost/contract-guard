// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Dependency-free ERC20-like asset for local dogfood only.
contract DogfoodAsset {
    string public name = "Dogfood Asset";
    string public symbol = "DFA";
    uint8 public decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    function mint(address to, uint256 amount) external {
        require(to != address(0), "zero receiver");
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "allowance");
        allowance[from][msg.sender] = allowed - amount;
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(to != address(0), "zero receiver");
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }
}

/// @notice Small ERC4626-style vault fixture for realistic Contract Guard CI dogfood.
contract TrainingVault {
    DogfoodAsset public immutable asset;
    address public owner;
    bool public paused;
    uint256 public totalShares;
    mapping(address => uint256) public sharesOf;

    event Deposit(address indexed caller, address indexed receiver, uint256 assets, uint256 shares);
    event Withdraw(address indexed caller, address indexed receiver, uint256 assets, uint256 shares);
    event Paused(bool paused);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    constructor(DogfoodAsset asset_) {
        asset = asset_;
        owner = msg.sender;
    }

    function setPaused(bool value) external onlyOwner {
        paused = value;
        emit Paused(value);
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function previewDeposit(uint256 assets) public pure returns (uint256) {
        return assets;
    }

    function previewWithdraw(uint256 assets) public pure returns (uint256) {
        return assets;
    }

    function deposit(uint256 assets, address receiver) external whenNotPaused returns (uint256 shares) {
        require(receiver != address(0), "zero receiver");
        require(assets > 0, "zero assets");
        shares = previewDeposit(assets);
        require(asset.transferFrom(msg.sender, address(this), assets), "transfer in");
        totalShares += shares;
        sharesOf[receiver] += shares;
        emit Deposit(msg.sender, receiver, assets, shares);
    }

    function withdraw(uint256 assets, address receiver) external whenNotPaused returns (uint256 shares) {
        require(receiver != address(0), "zero receiver");
        require(assets > 0, "zero assets");
        shares = previewWithdraw(assets);
        require(sharesOf[msg.sender] >= shares, "shares");
        sharesOf[msg.sender] -= shares;
        totalShares -= shares;
        require(asset.transfer(receiver, assets), "transfer out");
        emit Withdraw(msg.sender, receiver, assets, shares);
    }
}
