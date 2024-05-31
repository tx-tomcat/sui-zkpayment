import { Processor, Process } from '@nestjs/bull';
import { Job } from 'bull';
import {
  ADMIN_CAP,
  client,
  generate_input,
  PUBLISHED_AT,
  ZKRAMP_ID,
} from 'src/utils/generate-input';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import * as snarkjs from 'snarkjs';
import vkey from '../../zk/verification_key.json';

import { packedNBytesToString } from '@zk-email/helpers';
import Pusher from 'pusher';
import { Transaction } from '@mysten/sui/transactions';

const pusher = new Pusher({
  appId: '1804801',
  key: 'db73ad3fbe4d7d11395f',
  secret: 'fea9a55c1a14cdce2f8a',
  cluster: 'ap1',
  useTLS: true,
});
@Processor('proof-generate')
export class ProofVerifyConsumer {
  @Process()
  async transcode(job: Job<any>) {
    try {
      console.log('Job started', job.id);
      const input = await generate_input(job.data.eml);
      console.log('Input generated');

      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        './zk/wise_send.wasm',
        './zk/circuit_final.zkey',
      );
      console.log('Proof: ', publicSignals);
      console.log(JSON.stringify(proof, null, 1));
      const isVerify = await snarkjs.groth16.verify(vkey, publicSignals, proof);
      if (isVerify) {
        const bigIntMapper = publicSignals.map((x: string) => BigInt(x));
        console.log(bigIntMapper);
        const fromAddress = packedNBytesToString([bigIntMapper[1]]).slice(
          0,
          16,
        );
        const timestamp = packedNBytesToString([bigIntMapper[2]]).slice(0, 10);

        if (
          fromAddress === 'noreply@wise.com' &&
          Number(timestamp.trim()) * 1000 < new Date().getTime()
        ) {
          console.log('Verified');

          const txb = new Transaction();
          const adminKeypair = Ed25519Keypair.deriveKeypair(
            process.env.SEED_PHRASE,
          );

          txb.moveCall({
            target: `${PUBLISHED_AT}::core::admin_release_order_funds`,
            arguments: [
              txb.object(ADMIN_CAP),
              txb.object(ZKRAMP_ID),
              txb.pure(job.data.orderId),
            ],
          });
          txb.setSender(adminKeypair.toSuiAddress());
          txb.setGasBudget(10000000);
          const bytes = await txb.build({ client });

          const res = await client.signAndExecuteTransaction({
            transaction: bytes,
            signer: adminKeypair,
          });
          await pusher.trigger('p2p', 'message', {
            message: 'Deal closed with success',
            status: true,
          });
          console.log(res);
        }
      } else {
        pusher.trigger('p2p', 'message', {
          message: `"Invalid receipt! Proof is not valid for order ${job.data.orderId}}`,
          status: false,
        });
      }
    } catch (err) {
      console.log(err);
      return false;
    }
  }
}
