package com.jelurida.ardor.contracts;

import nxt.account.Account;
import nxt.addons.*;
import nxt.crypto.EncryptedData;
import nxt.http.callers.DecodeTokenCall;
import nxt.http.callers.GetBlockchainTransactionsCall;
import nxt.http.callers.SendMessageCall;
import nxt.http.callers.SetAccountPropertyCall;
import nxt.http.responses.TransactionResponse;
import nxt.util.Convert;
import nxt.util.Logger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import static nxt.blockchain.ChildChain.IGNIS;

/**
 * Challenge #3: Identity Verification Contract.
 * <p>
 * The flow to follow is
 * <ol>
 * <li>
 * To trigger the contract, send a message to the contract runner account with text
 * {"contract":"IdentityVerification", "params":{"operation": "GENERATE_CHALLENGE"}}, use prunable message.
 * In response the contract will generate challenge text and send a message transaction back to the sender with challengePlain and
 * challengeSignature values. Example response:
 * {"submittedBy":"IdentityVerification","challengeSignature":"e122c8bc547e29b4edbc60aa3b4c86bd2bea5a875064e54b92bf5ff273571c07bdd0fdbb705d63d8e32966430705557bbfdfb546fa91a1a7a57936a20057e272","publicSeed":"3858270124280833741","challengePlain":"python_76","source":"TRANSACTION"}
 * </li>
 * <li>
 * Generate token via https://testardor.jelurida.com/index.html Settings tag->Generate Token passing
 * as data the challengeSignature value from the message received.
 * </li>
 * <li>
 * Place the token into online resource, https://about.me owned by the sender. Example: https://about.me/nikolay.iv
 * Put the token into the bio info after the string "BlockchainToken: ".
 * </li>
 * <li>
 * Send a payment to the contract runner account with message text
 * {"contract":"IdentityVerification", "params":{"operation": "VALIDATE_CHALLENGE", "url":"[URL where token could be retrieved]"}}
 * Example message: {"contract":"IdentityVerification", "params":{"operation": "VALIDATE_CHALLENGE", "url":"https://about.me/nikolay.iv"}}
 * In response the contract will extract and validate token. If the validation is ok, the account of the sender
 * will be set with property "challenge" having the value of the challenge.
 * </li>
 * </ol>
 * <p>
 * The contract has following configurations
 * <ul>
 * <li>SecretPhrase of the contract, used for signing.</li>
 * <li>Required minimum payment to validate ownership of the online resource.</li>
 * <li>Option to encrypt the challenge text.</li>
 * <li>Option to generate random challenge text.</li>
 * <li>Maximum time between challenge generation request and challenge validation request.
 * Validation requests after this time will not be processed.</li>
 * </ul>
 * <p>
 * The contract supports validation ownership over profile at https://about.me site.
 * Example profile https://about.me/nikolay.iv
 */
@ContractInfo(version = "1.1.3")
public class IdentityVerification extends AbstractContract {

    public static final String CHALLENGE_PLAIN_KEY = "challengePlain";
    public static final String CHALLENGE_ENCRYPTED_KEY = "challengeEncrypted";
    public static final String CHALLENGE_SIGNATURE_KEY = "challengeSignature";


    public static final String[] CHALLENGE_PREFIX = {"horse", "tiger", "eagle", "dolphin", "panther", "elephant", "giraffe",
            "ant", "python", "gorilla"};

    @ContractParametersProvider
    public interface Params {

        @ContractRunnerParameter
        String secretPhrase();

        @ContractSetupParameter
        default long minPayment() {
            return IGNIS.ONE_COIN;
        }

        @ContractSetupParameter
        default boolean isEncryptedChallenge() {
            return false;
        }

        @ContractSetupParameter
        default boolean isRandomChallenge() {
            return true;
        }

        @ContractSetupParameter
        // maximum time between challenge generation request and challenge validation request. In seconds.
        default int expiryChallengeText() {
            return 3600 * 24 * 3;
        }
    }

    /**
     * processTransaction
     *
     * @param context the transaction context
     */
    @Override
    @ValidateContractRunnerIsRecipient
    @ValidateChain(accept = 2)
    public JO processTransaction(TransactionContext context) {
        switch (getOperation(context)) {
            case "GENERATE_CHALLENGE":
                return generateChallenge(context);
            case "VALIDATE_CHALLENGE":
                return validateToken(context);
            default:
                return context.getResponse();
        }
    }

    /**
     * Get request message type
     *
     * @param context
     * @return "GENERATE_CHALLENGE", "VALIDATE_CHALLENGE" or "" in case of unknown
     */
    private String getOperation(TransactionContext context) {
        Map<String, String> paramsRuntime = context.getRuntimeParams();
        if (paramsRuntime != null) {
            String operation = paramsRuntime.get("operation");
            if (operation != null) {
                return operation.toUpperCase();
            }
        }
        return "";
    }

    private JO generateChallenge(TransactionContext context) {
        Params paramsContract = context.getParams(Params.class);

        RandomnessSource r = context.initRandom(context.getRandomSeed());
        String challenge = paramsContract.isRandomChallenge() ?
                CHALLENGE_PREFIX[r.nextInt(CHALLENGE_PREFIX.length)] + "_" + r.nextInt(100) :
                CHALLENGE_PREFIX[r.nextInt(1)] + "_" + r.nextInt(1);

        // Sign the challenge
        byte[] signedChallenge = context.sign(challenge.getBytes(), paramsContract.secretPhrase());
        Logger.logInfoMessage("signedChallenge: " + Convert.toHexString(signedChallenge));

        // Compose the message
        TransactionResponse triggerTransaction = context.getTransaction();
        JO message = new JO();
        message.put(CHALLENGE_PLAIN_KEY, challenge);
        message.put(CHALLENGE_SIGNATURE_KEY, Convert.toHexString(signedChallenge));

        if (paramsContract.isEncryptedChallenge()) {
            // encrypted option if needed
            EncryptedData encryptedChallenge = Account.encryptTo(context.getPublicKey(paramsContract.secretPhrase()), Convert.toBytes(challenge, true), paramsContract.secretPhrase(), true);
            message.put(CHALLENGE_ENCRYPTED_KEY, Convert.toHexString(encryptedChallenge.getBytes()));
        }

        // Send a response message
        SendMessageCall sendMessageCall = SendMessageCall.create(triggerTransaction.getChainId()).
                recipient(triggerTransaction.getSenderRs()).
                message(message.toJSONString()).messageIsPrunable(true);
        return context.createTransaction(sendMessageCall);
    }

    private JO validateToken(TransactionContext context) {
        Params paramsConfig = context.getParams(Params.class);
        String resultText;
        // check for minimum payment
        if (context.getTransaction().getAmount() < paramsConfig.minPayment()) {
            resultText = String.format("Minimum payment of %d IGNIS is required", paramsConfig.minPayment() / IGNIS.ONE_COIN);
        } else {
            Map<String, String> paramsRuntime = context.getRuntimeParams();
            String url = paramsRuntime != null ? paramsRuntime.get("url") : null;

            if (url != null) {
                String token = null;
                try {
                    token = extractToken(url, (x) -> {
                                HTTPConnectionUtil util = new HTTPConnectionUtil();
                                JO resp = util.getResource(url);
                                String body = resp.getString("responseBody");
                                if (body != null) {
                                    int index = body.indexOf("BlockchainToken: ");
                                    if (index != -1) {
                                        return body.substring(index + 17, index + 17 + 160);
                                    }
                                }
                                throw new IOException("Could not find 'BlockchainToken' field");
                            }
                    );
                } catch (IOException e) {
                    Logger.logErrorMessage("Token extract from %s failure", url, e);
                }

                if (token != null) {
                    // set default message
                    resultText = "Challenge text could not be identified";

                    // get original challenge transation
                    TransactionResponse transaction = getChallengeTransaction(context);
                    if (transaction != null) {
                        JO jo = transaction.getAttachmentJson();
                        String trMessage = jo.getString("message");

                        JO trMessageJO = JO.parse(trMessage);
                        String orChallengePlain = trMessageJO.getString(CHALLENGE_PLAIN_KEY);
                        String orChallengeSignature = trMessageJO.getString(CHALLENGE_SIGNATURE_KEY);

                        // encrypted option if used
                        String orChallengeEncryptedBytes = trMessageJO.getString(CHALLENGE_ENCRYPTED_KEY);
                        if (orChallengeEncryptedBytes != null) {
                            orChallengePlain = new String(Account.decryptFrom(context.getPublicKey(paramsConfig.secretPhrase()), EncryptedData.readEncryptedData(Convert.parseHexString(orChallengeEncryptedBytes)), paramsConfig.secretPhrase(), true));
                        }

                        if (orChallengePlain != null && orChallengeSignature != null) {
                            // validation of signature
                            boolean verified = context.verify(Convert.parseHexString(orChallengeSignature), orChallengePlain.getBytes(), context.getPublicKey(paramsConfig.secretPhrase()));
                            if (!verified) {
                                // normally should not come here
                                resultText = "Contract signature is not valid";
                            }

                            JO result = DecodeTokenCall.create().token(token).website(orChallengeSignature).call();
                            if (result.getBoolean("valid")) {
                                // add account property
                                SetAccountPropertyCall setAccountPropertyCall = SetAccountPropertyCall.create(context.getChainOfTransaction().getId()).
                                        recipient(context.getSenderId()).
                                        property("challenge").value(orChallengePlain);
                                context.createTransaction(setAccountPropertyCall);
                                resultText = "Account challenge property is set";
                            } else {
                                resultText = "Token is not valid";
                            }
                        }
                    }
                } else {
                    resultText = "Token could not be extracted from URL parameter";
                }
            } else {
                resultText = "Request has missing URL parameter";
            }
        }
        // Compose the reply message
        TransactionResponse triggerTransaction = context.getTransaction();
        JO message = new JO();
        message.put("text", resultText);
        SendMessageCall sendMessageCall = SendMessageCall.create(triggerTransaction.getChainId()).
                recipient(triggerTransaction.getSenderRs()).
                message(message.toJSONString()).messageIsPrunable(true);
        return context.createTransaction(sendMessageCall);
    }

    /**
     * Get original transaction where contract has sent challenge text signature
     *
     * @param context
     * @return transaction or null if info could not be located
     */
    private TransactionResponse getChallengeTransaction(TransactionContext context) {
        Params paramsConfig = context.getParams(Params.class);
        int timestamp = context.getTransaction().getTimestamp() - paramsConfig.expiryChallengeText();
        if (timestamp < 0) {
            // just a protection if the blockchain has started recently
            timestamp = 0;
        }

        List<TransactionResponse> transactionList = GetBlockchainTransactionsCall.create(context.getTransaction().getChainId()).account(context.getTransaction().getSender()).timestamp(timestamp).type(1).subtype(0).getTransactions();
        return transactionList.stream().filter(t -> {
            if (!t.getRecipient().equals(context.getTransaction().getSender())) {
                return false;
            }
            JO jo = t.getAttachmentJson();
            if (jo != null) {
                String trMessage = jo.getString("message");
                if (trMessage != null) {
                    JO trMessageJO = JO.parse(trMessage);
                    return trMessageJO.isExist(CHALLENGE_SIGNATURE_KEY);
                }
            }
            return false;
        }).findFirst().orElse(null);
    }

    /**
     * Interface to extract token from given url.
     */
    public interface TokenExtractor {
        String extract(String url) throws IOException;
    }

    /**
     * Extract token using concrete extract interface
     *
     * @param host
     * @param extractor
     * @return extracted token or null in case of failure
     */
    private String extractToken(String host, TokenExtractor extractor) throws IOException {
        return extractor.extract(host);
    }

    /**
     * Utility to retrieve response of HTTP GET to an url.
     */
    public class HTTPConnectionUtil {
        public JO getResource(String urlString) throws IOException {
            BufferedReader rd = null;
            StringBuffer response = new StringBuffer();
            HttpURLConnection connection = null;

            try {
                URL url = new URL(urlString);
                connection = (HttpURLConnection) url.openConnection();

                connection.setRequestMethod("GET");
                //connection.setUseCaches(false);

                InputStream is;
                // Get Response
                if (connection.getResponseCode() >= HttpsURLConnection.HTTP_BAD_REQUEST) {
                    is = connection.getErrorStream();
                } else {
                    is = connection.getInputStream();
                }
                if (is != null) {
                    rd = new BufferedReader(new InputStreamReader(is));
                    String line;
                    while ((line = rd.readLine()) != null) {
                        response.append(line).append('\r');
                    }
                }
                JO httpResponse = new JO();
                httpResponse.put("responseCode", connection.getResponseCode());
                httpResponse.put("responseMessage", connection.getResponseMessage());
                httpResponse.put("responseBody", response);
                return httpResponse;
            } catch (IOException e) {
                throw e;
            } finally {
                if (rd != null) {
                    try {
                        rd.close();
                    } catch (IOException e) {
                    }
                }
                if (connection != null) {
                    connection.disconnect();
                }
            }
        }
    }
}



