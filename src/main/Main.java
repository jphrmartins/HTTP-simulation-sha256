package main;

import java.math.BigInteger;

import static main.Constant.*;

/**
 * Classe principal do sistema, tem como objetivo
 * "simular a execução de uma conversa utilizando o diffie-hellman"
 */
public class Main {
    public static void main(String[] args) throws Exception {
        var a = new BigInteger("987456321147852369854123698745213687563219854763214555462168");
        ConversationCipher conversationCipher = new ConversationCipher(a);

        System.out.println("Gerando a valor de A: " + conversationCipher.generateA().toString(16));
        System.out.println("Recebido valor de B: " + B.toString(16));
        System.out.println("Inicando a conversa..");
        conversationCipher.init(B, conversation -> {
            System.out.println("\nRecebendo primeira mensagem: " + FIRST_MESSAGE);
            String firstMessagePlainText = conversation.receiveMessage(FIRST_MESSAGE);
            System.out.println("PlainText da primeira mensagem: " + firstMessagePlainText);
            String reversedMessage = new StringBuilder(firstMessagePlainText).reverse().toString();
            System.out.println("Mensagem revertida: " + reversedMessage);
            String cipheredReverseMessage = conversation.sendMessage(reversedMessage);
            System.out.println("Mensagem revertida cifrada: " + cipheredReverseMessage);
            String decipheredReverseMessage = conversation.receiveMessage(cipheredReverseMessage);
            System.out.println("Tradução de teste da mensagem revertida: " + decipheredReverseMessage + "\n");
            System.out.println("Recebida segunda mensagem: " + SECOND_MESSGE);
            String plainTextSecondMessage = conversation.receiveMessage(SECOND_MESSGE);
            System.out.println("Texto claro da segunda mensagem: " + plainTextSecondMessage);
        });
    }
}