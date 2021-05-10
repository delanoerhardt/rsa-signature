# rsa-signature

Implementation of RSA-signing in python for computer security classes. Real use is not advised.

## Executar

Rodar usando python 3.9+ com o comando

´´´
python3 rsa_sig.py
´´´

## Como são geradas as chaves

O expoente público foi definido como sendo 65537 enquanto o expoente privado e o módulo foram obtidos através de um algoritmo de geração de chaves RSA.

Para gerar o módulo de l bits foi usado o seguinte algoritmo: primeiro é gerado um número aleatório p de l/2 bits, esse número tem seus dois bits mais significativos e seu bit menos significativos setados para serem igual a 1, é verificado se o número é primo e caso não seja, ele é incrementado em 2 até que um primo seja encontrado;o mesmo é feito para encontrar o segundo primo q, exceto que o tamanho do número aleatório gerado é de l-l/2 bits.

Em seguida é feita a multiplicação dos dois primos para encontrar o valor do módulo N e por último o valor do expoente privado é determinado pela inversa multiplicativa modular do expoente público módulo (p-1)(q-1).

Por fim a chave privada composta pelo módulo e pelo expoente privado é salva em um arquivo nomeado 'rsa-priv'. Uma vez que o expoente público foi fixado em um valor não se viu necessário salvá-la em um arquivo a parte.

### Verificar primalidade

Para verificar a primalidade dos candidatos a p e q foi implementado o teste de Miller-Rabin de acordo com o algoritmo encontrado [na Wikipedia](https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test).

## Como é assinado o arquivo

O arquivo é assinado seguindo o algoritmo proposto [na RFC onde RSASSA é descrito](https://datatracker.ietf.org/doc/html/rfc8017#section-8.2.1) de forma mais próxima
possível.

Primeiro é usado um algoritmo de hash - sha3 de 256 bits nesse caso - para criar um hash da mensagem a ser assinada.

À esse hash é anexado um DigestInfo contendo informações sobre o algoritmo de hash usado\*.

São adicionados bytes ao hash com DigestInfo de forma a atingir o mesmo comprimento em bits que o módulo N.

Então a assinatura resulta da exponenciação do hash com padding ao expoente privado módulo N, ou sign = paddedMessage^d % N.

Essa assinatura e o módulo N são armazenados num arquivo com nome igual ao nome do arquivo que contem a mensagem assinada mais um sufixo ".sign".

\* Foi usado o digest referente ao hash sha-256 ao invés do digest referente ao sha3_256 já que não encontrei a
especificação de como produzir esse digest corretamente a tempo.

## Verificação

A verificação é feita usando a assinatura gerado, o módulo N e o arquivo que contem a mensagem assinada.

A assinatura S é lida, bem como o módulo N, e é verificado se os primeiros 256 bits menos significativos de S ^ e % N correspondem ao valor obtido ao aplicar o hash à mensagem. Caso haja correspondência isso indica que a assinatura é válida.

## Formato usado

Para o armazenamento da chave privada foi escrito o valor do módulo e do expoente privado em duas linhas no arquivo chamado 'rsa-priv'.

No início de cada linha é escrito "rsa-priv-mod:" e "rsa-priv-key:" logo antes dos respectivos valores do módulo N e do expoente privado d para identificar ambos.

Para o armazenamento de cada assinatura segue-se um esquema semelhante, cria-se um arquivo com mesmo nom do arquivo que contem a mensagem a ser assinada mais o sufixo '.sign' e então o módulo N é escrito precedido por "key-mod:" em uma linha enquanto a assinatura S é escrita precedidada por "msg-sign:" na segunda linha.
