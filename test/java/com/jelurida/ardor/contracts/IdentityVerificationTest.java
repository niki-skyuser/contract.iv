package com.jelurida.ardor.contracts;

import nxt.addons.JO;
import nxt.blockchain.*;
import org.junit.Assert;
import org.junit.Test;

public class IdentityVerificationTest extends AbstractContractTest {

    @Test
    public void identity() {
        String contractName = ContractTestHelper.deployContract(IdentityVerification.class);

        // Send message to trigger the contract make challenge request
        JO messageJson = new JO();
        messageJson.put("contract", contractName);
        JO params = new JO();
        params.put("operation", "GENERATE_CHALLENGE");
        messageJson.put("params", params);
        String message = messageJson.toJSONString();
        ContractTestHelper.messageTriggerContract(message);
        // Contract should submit transaction now
        generateBlock();

        // Verify that the contract send back a message
        Block lastBlock = getLastBlock();
        for (FxtTransaction transaction : lastBlock.getFxtTransactions()) {
            for (ChildTransaction childTransaction : transaction.getSortedChildTransactions()) {
                if (ALICE.getAccount().getId() == (childTransaction.getSenderId())) {
                    JO messageBack = JO.parse(new String(childTransaction.getPrunablePlainMessage().getMessage()));
                    Assert.assertTrue(messageBack.isExist("challengeSignature"));
                    break;
                }
            }
        }

        // Send message to trigger the contract make token validation
        JO messageJson2 = new JO();
        messageJson2.put("contract", contractName);
        JO params2 = new JO();
        params2.put("operation", "VALIDATE_CHALLENGE");
        params2.put("url", "https://about.me/nikolay.iv");
        messageJson2.put("params", params2);
        String message2 = messageJson2.toJSONString();
        ContractTestHelper.bobPaysContract(message2, ChildChain.IGNIS, false);
        //ContractTestHelper.messageTriggerContract(message2);

        // Contract should submit transaction now
        generateBlock();

        // Verify that the contract send back a message
        Block lastBlock2 = getLastBlock();
        for (FxtTransaction transaction : lastBlock2.getFxtTransactions()) {
            for (ChildTransaction childTransaction : transaction.getSortedChildTransactions()) {
                if (ALICE.getAccount().getId() == (childTransaction.getSenderId())) {
                    JO messageBack = JO.parse(new String(childTransaction.getPrunablePlainMessage().getMessage()));
                    Assert.assertTrue(messageBack.isExist("text"));
                    break;
                }
            }
        }
    }
}
