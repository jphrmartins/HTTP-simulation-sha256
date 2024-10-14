package main;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;
import java.util.function.Consumer;

/**
 * Classe que contem todos os utilitário para operar a conversa
 * Aqui estão os métodos que conseguem cifrar e decifrar uma mensagem
 * Além disso, ela é reponsavel por começar o fluxo da conversa.
 */
public class ConversationCipher {

    /**
     * Valor de P, estabelicido anteriormente com o professor
     */
    private static final BigInteger P = new BigInteger(("B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6" +
            " 9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0" +
            " 13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70" +
            " 98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0" +
            " A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708" +
            " DF1FB2BC 2E4A4371").replaceAll(" ", ""), 16);

    /**
     * Valor de G, estabelicido anteriormente com o professor
     */
    private static final BigInteger G = new BigInteger(("A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F" +
            " D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213" +
            " 160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1" +
            " 909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A" +
            " D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24" +
            " 855E6EEB 22B3B2E5").replaceAll(" ", ""), 16);
    private MessageDigest digestor;
    private Cipher cipher;
    private BigInteger a;

    /**
     * Inicialização da classe, ja prepara os algoritmos que serão utilizado para o resto da conversa.
     * Como função resumo, será utilizado o alg. SHA-256
     * e para a criptgrafia será utilizado o alg. AEC no modo CBC com padding.
     *
     * @param a valor secreto de "a", passado no começo da inicialização do chat.
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    public ConversationCipher(BigInteger a) throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.a = a;
        digestor = MessageDigest.getInstance("SHA-256");
        cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
    }

    /**
     * Calcula o valor publico de A.
     * através da aritmética modular: (G ^ a) % P
     *
     * @return
     */
    public BigInteger generateA() {
        return G.modPow(a, P);
    }

    /**
     * Inicialização da conversa.
     * ao receber o valor fornecido pelo professor de "B", é capaz de gerar o valor comum e secreto de V.
     * através de aritmética modular. (B ^ a) % P.
     * Sabendo que B foi gerado da seguinte forma (G ^ b) % P
     * é possivel concluir que o valor de V é (G ^ a ^ b) % P, o que pode ser reduzido a (G ^ (a * b)) % P
     * com isso é possivel concluir que tanto o professor quanto o aluno possuem o mesmo valor de V.
     * <p>
     * Em seguida o méotdo gera o hash (SHA-256) do valor V e seleciona os primeiros 128 bits, para utilizar como senha
     * para a cifragem.
     * e então inicia o DSL de conversa.
     *
     * @param B            Valor passado pelo professor para realizar o caluclo de V
     * @param conversation operação que permite o uso da DSL ConversationThreadSim
     */
    public void init(BigInteger B, Consumer<ConversationThreadSim> conversation) {
        var V = B.modPow(a, P);
        System.out.println("Gerado valor de V -> (B^a)%P -> (" +
                B.toString(16) + " ^ " + a.toString(16) + ") % " + P.toString(16));
        System.out.println("V = " + V.toString(16));
        var S = this.hashOf(V);
        /*
         * Devido a possibilidade do toByteArray gerar o primeiro indice [0] como 0, para representar o byte de sinal.
         * é necessário realizar a logica abaixo para poder pegar os primeiros 128 bits corretos.
         */
        var bytePassword = S.toByteArray()[0] == 0
                ? Arrays.copyOfRange(S.toByteArray(), 1, 17)
                : Arrays.copyOfRange(S.toByteArray(), 0, 16);
        new ConversationThreadSim(this, bytePassword).operate(conversation);
    }

    /**
     * Gera o hash SHA-256 do bigInteger value
     *
     * @param value
     * @return
     */
    private BigInteger hashOf(BigInteger value) {
        return new BigInteger(digestor.digest(value.toByteArray()));
    }

    /**
     * Executa a cifragem ou decifragem da mensagem junto ao seu IV.
     *
     * @param message
     * @param iv
     * @param keySpec
     * @param mode
     * @return
     */
    private byte[] executeCiphering(byte[] message, byte[] iv, SecretKeySpec keySpec, int mode) {
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        try {
            cipher.init(mode, keySpec, ivSpec);
            return cipher.doFinal(message);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Devido a possibilidade do toByteArray gerar o primeiro indice [0] como 0, para representar o byte de sinal.
     * é necessário essa logica, para ser capaz de pegar os verdadeiros valores binarios do numero.
     *
     * @param bytes
     * @return
     */
    private static byte[] removeLeading0(byte[] bytes) {
        return bytes.length > 1 && bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
    }

    /**
     * DSL que permite que seja possivel representar a conversa de forma mais "natural" na Main
     */
    public class ConversationThreadSim {
        private final ConversationCipher cipher;
        private final SecretKeySpec password;

        /**
         * Incializador, recebe o utilitario conversationCipher para usar os métodos de cifragem e decifragem.
         * e os bytes (128 bits) da senha.
         * @param conversationCipher
         * @param password
         */
        private ConversationThreadSim(ConversationCipher conversationCipher, byte[] password) {
            this.cipher = conversationCipher;
            this.password = new SecretKeySpec(password, "AES");
        }

        /**
         * Recebe a mensagem no padrão:  [iv 128 bits][message]
         * Divide em iv e mensagem
         * pega os respectivos valores em bytes.
         * remove o possivel 0 inicial gerado pelo toByteArray da classe BigInteger.
         * executa a decifragem da mensagem
         * Responde com a texto puro da mensagem recebida.
         * @param ivWithMessage
         * @return
         */
        public String receiveMessage(String ivWithMessage) {
            String iv = ivWithMessage.substring(0, 32);
            String message = ivWithMessage.substring(32);
            byte[] byteMessage = new BigInteger(message, 16).toByteArray();
            byte[] byteIv = new BigInteger(iv, 16).toByteArray();
            byte[] trimmedMessage = removeLeading0(byteMessage);
            byte[] trimmedIv = removeLeading0(byteIv);

            var byteResultMessage = cipher.executeCiphering(trimmedMessage, trimmedIv, password, Cipher.DECRYPT_MODE);
            return new String(byteResultMessage);
        }

        /**
         *  /**
         * Recebe a mensagem pura, o texto puro que deve ser enviado
         * Gera um Iv aleatório.
         * - Gerar um valor aleatório de 125 bits.
         * - Realiza o hash SHA-256 do valor gerado.
         * - Pega os primeiros 128 bits
         * Executa a cifragem da mensagem, passando os bytes da mensagem, iv a senha.
         * concateca o valor em Hexa do IV + o valor em Hexa da mensagem.
         * retorna o valor gerado.
         * @param message
         * @return
         */
        public String sendMessage(String message) {
            var sendIv = Arrays.copyOf(cipher.hashOf(new BigInteger(125, new Random())).toByteArray(), 16);
            byte[] cipheredMessage = cipher.executeCiphering(message.getBytes(), sendIv, password, Cipher.ENCRYPT_MODE);
            return new BigInteger(1, sendIv).toString(16) + new BigInteger(1, cipheredMessage).toString(16);
        }


        /**
         * Inicializador da DSL, recebe um Consumer de si mesmo, a fim de diponibilizar os métodos publicos
         * ao classe utilizadora.
         * @param conversation
         */
        private void operate(Consumer<ConversationThreadSim> conversation) {
            conversation.accept(this);
        }
    }
}
