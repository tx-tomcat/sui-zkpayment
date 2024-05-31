
<div align="center">
<h1 align="center">
<h3>◦ Don't waste your time with KYC, use ZKPayment.</h3>
</div>


## 📖 Table of Contents
- [📍 Overview](#-overview)
- [🛣 Roadmap](#-roadmap)
- [🚀 Getting started](#-getting-started)
- [ Contract Deployment](#contract-deployment)
- [ Acknowledgments](#acknowledgments)


## 📍 Overview

The goal is to create a liquidity marketplace where users can directly transfer funds without the requirement of KYC, based on ZK-Email technology. This eliminates the need for the ramp to function as an intermediary.

**The steps are simple:**
- The seller escrows funds to the smart contract, sets a price, and adds their payment key (Wise). A collateral is collected to ensure the token transfer to the buyer.
- The buyer selects a liquidity pool to make a purchase. An intermediate state is established, and the buyer has 1 hour to make the off-chain payment.
- Upon receiving the email notification, the buyer uploads the email notification, creates the ZK proof, and submits it via our ZK API process.
- The ZK API verifies the proof and the funds are transferred to the buyer.

### Architecture
ZKPayment uses Zero-Knowledge (ZK) proofs to verify DKIM signatures in payment confirmation emails. Therefore, users must have notification emails enabled in their payment providers. This technology is powered by ZK-Email, a new technology that utilizes regex and other email features to create ZK proofs. Currently, we do not store the ZK proof on-chain. The entire ZK process is conducted through an API.

**Tech Stack:**
- Circuits: Responsible for verifying transaction details, and preserving the confidentiality of confidential information.
- Smart Contracts: Smart contracts enable trustless transactions and handle the protocol's logic.
- Front-end: The UI serves as the front end that enables users to interact with the protocol.


## 🛣 Roadmap

> - [X] `ℹ️  Implement ZKEmail circuit`
> - [X] `ℹ️  Implement Sui smart contract`
> - [X] `ℹ️  Implement front-end UI`
> - [X] `ℹ️  Implement support to Wise`
> - []  `ℹ️  Implement ZK validator on-chain`
> - []  `ℹ️  Implement support to Brazil PIX`
> - []  `ℹ️  Implement support to Vemno`
> - []  `ℹ️  Implement support to Canada Interac`


## 🚀 Getting started 

### 1. Run the frontend

The frontend works out of the box, without a local node running, as the sample contract is pre-deployed on certain live testnets (i.e. `Sui-testnet`). Necessary deployment metadata and addresses are provided under `contracts/deployments/`.

> **Pre-requisites:**
>
> - Setup Node.js v18+ (recommended via [nvm](https://github.com/nvm-sh/nvm) with `nvm install 18`)
> - Install [pnpm](https://pnpm.io/installation) (recommended via [Node.js Corepack](https://nodejs.org/api/corepack.html) or `npm i -g pnpm`)
> - Clone this repository


## Acknowledgments
This project was inspired by the idea from [ZKP2P](https://github.com/zkp2p).
