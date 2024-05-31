module zkramp::core {
    use sui::balance::{ Balance};
    use sui::clock::{ Clock, timestamp_ms};
    use std::option::{ is_some, destroy_some};
    use std::string::{Self ,String};
    use sui::sui::SUI;
    use sui::table::{Self, Table};
    use sui::coin::{ Coin, into_balance};
    use sui::groth16;
    use sui::event;
    use zkramp::string_utils;
    const ORDER_STATUS_OPEN: u8 = 0;
    const ORDER_STATUS_FILLED: u8 = 1;
    const ORDER_STATUS_CANCELED: u8 = 2;

    const CLAIM_STATUS_WAITING_FOR_BUYER_PROOF: u8 = 3;
    const CLAIM_STATUS_WAITING_FOR_SELLER_PROOF: u8 = 4;
    const CLAIM_STATUS_FILLED: u8 = 5;
    const CLAIM_STATUS_CANCELED: u8 = 6;

    const E_INVALID_ORDER_STATUS_CHANGE: u64 = 1;
    const E_ORDER_CLAIMED: u64 = 2;
    const E_ORDER_NOT_FOUND: u64 = 3;
    const E_UNAUTHORIZED: u64 = 4;
    const E_PROOF_EXPIRED: u64 = 5;
    const E_INVALID_EMAIL_SENDER: u64 = 6;


    public struct Order has store {
        order_id: u64,
        owner: address,
        total: Balance<SUI>,
        amount_to_send: u64,
        collateral: u64,
        amount_to_receive: String,
        status: u8,
        payment_key: String,
        hash_name: String,
    }

    public struct OrderEntry has store, copy, drop {
        order_id: u64,
        owner: address,
        total: u64,
        amount_to_send: u64,
        collateral: u64,
        amount_to_receive: String,
        status: u8,
        payment_key: String,
        hash_name: String,
    }

    public struct OrderClaim has copy, store, drop {
        order_id: u64,
        buyer: address,
        status: u8,
        claim_expiration_time: u64,
    }

    public struct ZKRamp has key, store {
        id: UID,
        orders: Table<u64, Order>,
        order_claims: Table<u64, OrderClaim>,
        order_list: vector<OrderEntry>,
        order_claim_list: vector<OrderClaim>,
        owner: address,
        next_order_nonce: u64
    }

    public struct VerifiedEvent has copy, drop {
        order_claim_id: u64,
        is_verified: bool,
        from: String,
        timestamp: u64,
    }

    public struct AdminCap has key { id: UID }

    // INIT
    fun init(ctx: &mut TxContext) {
        let owner = tx_context::sender(ctx);
        transfer::share_object(ZKRamp {
            id: object::new(ctx),
            orders: table::new(ctx),
            order_claims: table::new(ctx),
            order_list: vector::empty(),
            order_claim_list: vector::empty(),
            owner,
            next_order_nonce: 0
        });
        transfer::transfer(AdminCap {
            id: object::new(ctx)
        }, ctx.sender())
    }


    // CREATE ORDER
    public entry fun create_order(
        ramp: &mut ZKRamp, coin: Coin<SUI>, payment_key: String, hash_name: String,
        amount_to_receive: String,
        ctx: &mut TxContext
    ) {
        let balance = coin.into_balance();
        let amount = balance.value();
        let order = Order {
            order_id: ramp.next_order_nonce,
            owner: tx_context::sender(ctx),
            total: balance,
            amount_to_send: amount * 95 / 100,
            collateral: amount * 5 / 100,
            status: ORDER_STATUS_OPEN,
            amount_to_receive: amount_to_receive,
            payment_key,
            hash_name,
        };

        let order_entry = OrderEntry {
            order_id: order.order_id,
            owner: order.owner,
            total: order.total.value(),
            amount_to_send: order.amount_to_send,
            collateral: order.collateral,
            status: order.status,
            amount_to_receive: order.amount_to_receive,
            payment_key: order.payment_key,
            hash_name: order.hash_name,
        };
        vector::push_back(&mut ramp.order_list, order_entry);
        table::add(&mut ramp.orders, ramp.next_order_nonce, order);
        ramp.next_order_nonce = ramp.next_order_nonce + 1;
    }

    public entry fun claim_order(
        ramp: &mut ZKRamp, order_id: u64, claim_expiration_time: u64, ctx: &mut TxContext
    ) {
         let order = table::borrow_mut(&mut ramp.orders, order_id);
        assert!(order.status == ORDER_STATUS_OPEN, E_INVALID_ORDER_STATUS_CHANGE);
        assert!(!is_exists_order_claim(order_id, ramp), E_ORDER_CLAIMED);
        let order_claim = OrderClaim {
                order_id,
                buyer: tx_context::sender(ctx),
                status: CLAIM_STATUS_WAITING_FOR_BUYER_PROOF,
                claim_expiration_time,
            };
        vector::push_back(&mut ramp.order_claim_list, order_claim);
        table::add(&mut ramp.order_claims, order_id, order_claim);
    }

    public fun get_value(balance: &Balance<SUI>) : u64 {
        balance.value()
    }

    public fun is_exists_order(order_id:u64,  ramp: &ZKRamp): bool {
        table::contains(&ramp.orders, order_id)
    }

    public fun is_exists_order_claim(order_claim_id: u64, ramp: &ZKRamp): bool {
        table::contains(&ramp.order_claims, order_claim_id)
    }

    public fun verify_proof(ramp: &mut ZKRamp, vk_bytes: vector<u8>, public_inputs_bytes: vector<u8>, proof_points_bytes: vector<u8>, order_claim_id: u64, ctx: &mut TxContext) {
        let pvk = groth16::prepare_verifying_key(&groth16::bn254(), &vk_bytes);
        let public_inputs = groth16::public_proof_inputs_from_bytes(public_inputs_bytes);
        let proof_points = groth16::proof_points_from_bytes(proof_points_bytes);
        let is_verified = groth16::verify_groth16_proof(&groth16::bn254(), &pvk, &public_inputs, &proof_points);

        if(is_verified){
            let mut from_pack = vector::empty();
            let from_pack_index_in_signals = 1;
            let mut i = from_pack_index_in_signals;

            while (i < from_pack_index_in_signals + 1) {
                vector::push_back(&mut from_pack, *vector::borrow(&public_inputs_bytes, i));
                i = i + 1;
            };
            let send_from = string_utils::convert_packed_bytes_to_string(from_pack, 31, 31);

            let mut timestamp_pack = vector::empty();
            let timestamp_pack_index_in_signals = 2;
            let mut i = timestamp_pack_index_in_signals;

            while (i < timestamp_pack_index_in_signals + 1) {
                vector::push_back(&mut timestamp_pack, *vector::borrow(&public_inputs_bytes, i));
                i = i + 1;
            };
            let order_claim= table::borrow_mut(&mut ramp.order_claims, order_claim_id);

            let timestamp_string = string_utils::convert_packed_bytes_to_string(timestamp_pack, 31, 31);
            let timestamp = string_utils::string_to_u64(timestamp_string);
            assert!(timestamp < order_claim.claim_expiration_time, E_PROOF_EXPIRED);
            assert!(send_from == string::utf8(b"noreply@wise.com"), E_INVALID_EMAIL_SENDER);
            event::emit(VerifiedEvent {is_verified: is_verified, order_claim_id: order_claim_id, from : send_from, timestamp: timestamp});
            release_order_funds(ramp, order_claim_id, ctx);
        } else {
            event::emit(VerifiedEvent {is_verified: is_verified, order_claim_id: order_claim_id, from : string::utf8(b"error"), timestamp: 0});
        }
    }

    public entry fun admin_release_order_funds(_: &AdminCap, ramp: &mut ZKRamp, order_claim_id: u64, ctx: &mut TxContext) {
        assert!(is_exists_order_claim(order_claim_id, ramp), E_ORDER_NOT_FOUND);
        assert!(ramp.owner == tx_context::sender(ctx), E_UNAUTHORIZED);
        release_order_funds(ramp, order_claim_id, ctx);
    }
 
    // CANCEL ORDER
    public entry fun cancel_order(ramp: &mut ZKRamp, order_id: u64, clock: &Clock, ctx: &mut TxContext) {
        assert!(is_exists_order(order_id, ramp), E_ORDER_NOT_FOUND);
        let order = table::borrow_mut(&mut ramp.orders, order_id);
        assert!(order.status == ORDER_STATUS_OPEN, E_INVALID_ORDER_STATUS_CHANGE);
        assert!(order.owner == tx_context::sender(ctx), E_UNAUTHORIZED);
        assert!(check_order_claim(ramp, order_id, clock) == 0, E_ORDER_CLAIMED);
        let order= table::borrow_mut(&mut ramp.orders, order_id);
        order.status = ORDER_STATUS_CANCELED;
        transfer::public_transfer(order.total.withdraw_all().into_coin(ctx), order.owner);
    }
    
    // CANCEL CLAIMED ORDER
    public entry fun cancel_claim_order(ramp: &mut ZKRamp, order_claim_id: u64, ctx: &mut TxContext) {
        assert!(is_exists_order_claim(order_claim_id, ramp), E_ORDER_NOT_FOUND);
        let order_claim = table::borrow_mut(&mut ramp.order_claims, order_claim_id);
        assert!(order_claim.status == CLAIM_STATUS_WAITING_FOR_BUYER_PROOF, E_INVALID_ORDER_STATUS_CHANGE);
        assert!(order_claim.buyer == tx_context::sender(ctx), E_UNAUTHORIZED);
        let order_claims = table::borrow_mut(&mut ramp.order_claims, order_claim_id);
        order_claims.status = CLAIM_STATUS_CANCELED;
    }
    
    // UPDATE CLAIM STATUS
    public entry fun update_claim_order_status(
        ramp: &mut ZKRamp,
        order_claim_id: u64,
        status: u8,
        claim_expiration_time: Option<u64>,
        ctx: &mut TxContext
    ) {
        assert!(is_exists_order_claim(order_claim_id, ramp), E_ORDER_NOT_FOUND);
        let order_claim = table::borrow_mut(&mut ramp.order_claims, order_claim_id);
        assert!(
            ramp.owner == tx_context::sender(ctx),
            E_UNAUTHORIZED
        );
        assert!(
            order_claim.status == CLAIM_STATUS_WAITING_FOR_BUYER_PROOF || order_claim.status == CLAIM_STATUS_WAITING_FOR_SELLER_PROOF,
            E_INVALID_ORDER_STATUS_CHANGE
        );
    
        if (status == CLAIM_STATUS_FILLED) {
            release_order_funds(ramp, order_claim_id, ctx);
        } else {
            order_claim.status = status;
            if (status == CLAIM_STATUS_WAITING_FOR_SELLER_PROOF) {
                assert!(
                    is_some(&claim_expiration_time),
                    E_INVALID_ORDER_STATUS_CHANGE
                );
                order_claim.claim_expiration_time = destroy_some(claim_expiration_time);
            };
        };
    }
    
    // BUYER CLAIM FUNDS (IF TIME EXPIRES)
    public entry fun buyer_claim_order_funds(ramp: &mut ZKRamp, order_claim_id: u64, clock: &Clock, ctx: &mut TxContext) {
        assert!(is_exists_order_claim(order_claim_id, ramp), E_ORDER_NOT_FOUND);
        let order_claim = table::borrow_mut(&mut ramp.order_claims, order_claim_id);
        assert!(order_claim.status == CLAIM_STATUS_WAITING_FOR_SELLER_PROOF && order_claim.status == CLAIM_STATUS_WAITING_FOR_BUYER_PROOF, E_INVALID_ORDER_STATUS_CHANGE);
        assert!(order_claim.buyer == tx_context::sender(ctx), E_UNAUTHORIZED);
        assert!(order_claim.claim_expiration_time < clock.timestamp_ms(), E_ORDER_CLAIMED);
        release_order_funds(ramp, order_claim_id, ctx);
    }
    
    // INTERNAL FUNCTION TO RELEASE FUNDS
    fun release_order_funds(ramp: &mut ZKRamp, order_claim_id: u64, ctx: &mut TxContext) {
        let order_claim = table::borrow_mut(&mut ramp.order_claims, order_claim_id);
        let order_id = order_claim.order_id;
        let order = table::borrow_mut<u64, Order>( &mut ramp.orders, order_id);
        order_claim.status = CLAIM_STATUS_FILLED;
        order.status = ORDER_STATUS_FILLED;
        let mut i = 0;
        while (i < vector::length(&ramp.order_claim_list)) { 
            let item = vector::borrow_mut(&mut ramp.order_claim_list, i);
            if (item.order_id == order_claim_id) {
                item.status = CLAIM_STATUS_FILLED;
                break
            };
            i = i + 1;
        };
        let mut j = 0;
        while (j < vector::length(&ramp.order_list)) { 
            let item = vector::borrow_mut(&mut ramp.order_list, i);
            if (item.order_id == order_id) {
                item.status = ORDER_STATUS_FILLED;
                break
            };
            j = j + 1;
        };
        let fee_amount = order.collateral;
        let owner_fee = order.total.split(fee_amount);
        let send_amount = order.total.split(order.amount_to_send);
        transfer::public_transfer(owner_fee.into_coin(ctx), ramp.owner);
        transfer::public_transfer(order.total.withdraw_all().into_coin(ctx), order.owner);
        transfer::public_transfer(send_amount.into_coin(ctx), order_claim.buyer); // Funds to buyer
    }

    fun check_order_claim(ramp: &ZKRamp, order_claim_id: u64, clock: &Clock): u64{
        let order_claim = table::borrow(&ramp.order_claims, order_claim_id);
        if(is_exists_order_claim(order_claim_id, ramp) && order_claim.status != CLAIM_STATUS_CANCELED && order_claim.claim_expiration_time > clock.timestamp_ms()){
            return E_ORDER_CLAIMED
        };
        0
    }
    
}
