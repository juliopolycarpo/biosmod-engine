# Publicar um catálogo

[English](../../guide/publishing.md) | Português (Brasil)

Um catálogo publicado é um repositório git criado com `bme catalog init` ou `bme catalog split` ([catálogos](catalogs.md#iniciar-um-repositório-de-dispositivo)). A cada release você assina o `catalog.json` com minisign e cria uma tag no commit. Os usuários registram a URL raw do `catalog.json` de uma tag, junto com a sua chave pública.

## O que o repositório contém

O git rastreia os diretórios do catálogo, `notes/`, `catalog.json`, `catalog.json.minisig`, `README.md`, `LICENSE*`, `.github/`, `.gitignore` e `.gitattributes`. O restante do nível superior fica local, e o `.gitignore` ignora, em todos os diretórios, imagens de firmware, módulos extraídos, tabelas ACPI, arquivos compactados, PDFs e arquivos de chave. O `README.md` que `catalog init` gera traz a lista completa e as verificações a fazer em arquivos de `notes/` e `provenance/` antes do commit: números de série, endereços MAC, código de fornecedor e caminhos da sua máquina.

Mantenha a chave secreta fora do repositório. Por padrão, o `minisign` a guarda em `~/.minisign/`.

`catalog init` também escreve `.github/workflows/validate.yml`. A cada push e pull request ele instala o `bme` e executa `bme catalog index . --check` e `bme catalog validate .`. O `README.md` gerado diz qual `bme` ele instala.

## Release

```sh
# aumente "version" em catalog.json
bme catalog index .
bme catalog validate .
minisign -S -s ~/.minisign/acme-x99.key -m catalog.json
minisign -V -H -p ~/.minisign/acme-x99.pub -m catalog.json
git add catalog.json catalog.json.minisig
git commit -m "chore(release): 0.2.0"
git tag v0.2.0
git push origin main v0.2.0
```

Assine por último. A assinatura cobre os bytes exatos de `catalog.json`, então qualquer `bme catalog index` posterior que altere o arquivo a invalida.

Altere `version` somente em um commit de release. O `bme catalog update` guarda cada versão que aceitou com o digest do seu manifesto e recusa dois casos:

- uma versão já aceita, com conteúdo diferente: `version 0.2.0 was accepted with different content (<digest>)`;
- uma versão mais antiga que a mais nova já aceita: `version 0.1.0 is older than the accepted 0.2.0 (rollback refused)`.

Um commit de registro altera o `catalog.json`, porque o índice guarda o tamanho e o SHA-256 de cada arquivo. Se dois estados publicados do `catalog.json` compartilhassem uma versão, quem aceitou o primeiro teria o segundo recusado. Aumentar a versão no commit de release e publicar apenas commits com tag dá a cada versão publicada um único conteúdo. Uma release errada é substituída por uma versão maior, nunca por uma nova tag no mesmo nome.

## Assinar

Instale o `minisign` pela sua distribuição ou por [jedisct1/minisign](https://github.com/jedisct1/minisign). Crie o par de chaves uma vez, fora do repositório:

```sh
minisign -G -p ~/.minisign/acme-x99.pub -s ~/.minisign/acme-x99.key
```

`-G` pede uma senha para a chave secreta (`-W` dispensa). Assine o `catalog.json` no diretório onde ele está:

```sh
minisign -S -s ~/.minisign/acme-x99.key -m catalog.json
```

O `minisign` grava a assinatura em `<arquivo>.minisig`, aqui `catalog.json.minisig`, e o `bme catalog update` baixa esse nome ao lado do `catalog.json`. O `bme` aceita uma assinatura com estas propriedades:

- Ela é pré-hasheada: a segunda linha do arquivo começa com `RU`. O `minisign -S` gera uma assim por padrão; `-l` gera uma assinatura legada (`RW`), que o `bme` recusa.
- Ela traz a linha `trusted comment:` e a assinatura global que a segue, que o `minisign -S` sempre escreve. Uma assinatura do `signify` do OpenBSD não tem nenhuma das duas e é recusada. Não edite o comentário confiável, pois a assinatura global o cobre; o comentário não confiável pode mudar livremente.
- O id da chave dela coincide com a chave pública informada pelo usuário.

## Consumir uma release

```sh
bme catalog add acme-x99 https://raw.githubusercontent.com/<owner>/<repo>/v0.2.0/catalog.json --trust-key <public key>
bme catalog update acme-x99
bme scan dump.bin --catalog acme-x99
```

`--trust-key` aceita a linha base64 da chave pública (ela começa com `RW`) ou o caminho do arquivo `.pub`. O `bme catalog update` baixa `catalog.json` e `catalog.json.minisig`, confere a assinatura e então busca cada arquivo indexado na URL do `catalog.json`, com o nome do arquivo trocado pelo caminho indexado (`patches/B01.json` vira `https://raw.githubusercontent.com/<owner>/<repo>/v0.2.0/patches/B01.json`). [Fontes e confiança](trust.md) lista as verificações seguintes.

- Registre uma tag, nunca um branch. Uma URL de branch falha na verificação depois de qualquer commit que altere `catalog.json` sem uma nova assinatura, o que inclui todo commit de registro. O `-H` acima faz o `minisign` recusar uma assinatura legada como o `bme` recusa; o minisign anterior à versão 0.10 não usa pré-hash por padrão.
- Um catálogo em um subdiretório de um repositório usa o subdiretório na URL, e o `catalog.json.minisig` fica ao lado do `catalog.json`: `https://raw.githubusercontent.com/<owner>/<repo>/v0.2.0/boards/acme-x99/catalog.json`.
- `catalog add` recusa um alias já registrado. Para passar a uma tag mais nova, execute `bme catalog remove acme-x99`, adicione a nova URL com o mesmo alias e atualize. O `remove` mantém as versões aceitas, então a verificação de rollback continua valendo; `--purge` as apaga.

Para usar um catálogo sem assinatura, clone-o, faça o checkout da tag e carregue o diretório:

```sh
git clone --branch v0.2.0 https://github.com/<owner>/<repo> acme-x99
bme scan dump.bin --catalog ./acme-x99 --allow-unsigned-local
```

Um plano construído a partir dele registra a confiança `unsigned-local`. Um clone registrado ainda pode verificar a assinatura: `bme catalog add acme-x99 ./acme-x99 --trust-key <public key>` confere `catalog.json.minisig` no local.

## Entregue a chave pública fora do repositório

Uma chave commitada ao lado do `catalog.json` não prova nada: quem pode alterar o catálogo pode alterar a chave ao lado dele. Publique a chave pública em um lugar onde o leitor possa compará-la com outra fonte, como a página do projeto, uma nota de release ou uma mensagem sua, e diga aos usuários que a passem a `--trust-key`. O `bme` nunca lê uma chave de dentro de um catálogo.

## Ligar catálogos

O campo opcional `repository` do `catalog.json` nomeia o repositório (`bme catalog init --repository URL`), e o `bme catalog merge` o copia para `sources`, ao lado do commit e do digest de cada catálogo mesclado; veja [Compartilhar registros entre placas](catalogs.md#compartilhar-registros-entre-placas).

## Decisão: sem atalho `github:`

`bme catalog add` recebe uma URL `https://` completa. Não existe a forma `github:owner/repo[/path][@ref]`. A URL mostra a referência fixada pelo usuário, e o `bme` aplica as mesmas verificações a qualquer host que sirva arquivos raw por HTTPS.
