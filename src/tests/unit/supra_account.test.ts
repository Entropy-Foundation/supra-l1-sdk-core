// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

import {
  SupraAccount,
  SupraAccountObject,
  getAddressFromAccountOrAddress,
} from "../../account";
import { HexString } from "../../utils";
import nacl from "tweetnacl";
import * as bip39 from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import util from "util";

const supraAccountObject: SupraAccountObject = {
  address: "0x978c213990c4833df71548df7ce49d54c759d6b6d932de22b24d56060b7af2aa",
  privateKeyHex:
    // eslint-disable-next-line max-len
    "0xc5338cd251c22daa8c9c9cc94f498cc8a5c7e1d2e75287a5dda91096fe64efa5de19e5d1880cac87d57484ce9ed2e84cf0f9599f12e7cc3a52e4e7657a763f2c",
  publicKeyHex:
    "0xde19e5d1880cac87d57484ce9ed2e84cf0f9599f12e7cc3a52e4e7657a763f2c",
};

const mnemonic =
  "shoot island position soft burden budget tooth cruel issue economy destroy above";

test("generates random accounts", () => {
  const a1 = new SupraAccount();
  const a2 = new SupraAccount();
  expect(a1.authKey()).not.toBe(a2.authKey());
  expect(a1.address().hex()).not.toBe(a2.address().hex());
});

test("generates derive path accounts", () => {
  const address =
    "0x07968dab936c1bad187c60ce4082f307d030d780e91e694ae03aef16aba73f30";
  const a1 = SupraAccount.fromDerivePath("m/44'/637'/0'/0'/0'", mnemonic);
  expect(a1.address().hex()).toBe(address);
});

test("generates derive path accounts", () => {
  expect(() => {
    SupraAccount.fromDerivePath("", mnemonic);
  }).toThrow(new Error("Invalid derivation path"));
});

test("accepts custom address", () => {
  const address = "0x777";
  const a1 = new SupraAccount(undefined, address);
  expect(a1.address().hex()).toBe(address);
});

test("Deserializes from SupraAccountObject", () => {
  const a1 = SupraAccount.fromSupraAccountObject(supraAccountObject);
  expect(a1.address().hex()).toBe(supraAccountObject.address);
  expect(a1.pubKey().hex()).toBe(supraAccountObject.publicKeyHex);
});

test("Deserializes from SupraAccountObject without address", () => {
  const privateKeyObject = { privateKeyHex: supraAccountObject.privateKeyHex };
  const a1 = SupraAccount.fromSupraAccountObject(privateKeyObject);
  expect(a1.address().hex()).toBe(supraAccountObject.address);
  expect(a1.pubKey().hex()).toBe(supraAccountObject.publicKeyHex);
});

test("Serializes/Deserializes", () => {
  const a1 = new SupraAccount();
  const a2 = SupraAccount.fromSupraAccountObject(a1.toPrivateKeyObject());
  expect(a1.authKey().hex()).toBe(a2.authKey().hex());
  expect(a1.address().hex()).toBe(a2.address().hex());
});

test("Signs and verifies strings", () => {
  const a1 = SupraAccount.fromSupraAccountObject(supraAccountObject);
  const messageHex = "0x7777";
  const expectedSignedMessage =
    "0xc5de9e40ac00b371cd83b1c197fa5b665b7449b33cd3cdd305bb78222e06a671a49625ab9aea8a039d4bb70e275768084d62b094bc1b31964f2357b7c1af7e0d";
  expect(a1.signHexString(messageHex).hex()).toBe(expectedSignedMessage);
  expect(a1.verifySignature(messageHex, expectedSignedMessage)).toBe(true);
  expect(a1.verifySignature(messageHex + "00", expectedSignedMessage)).toBe(
    false,
  );
});

test("Gets the resource account address", () => {
  const sourceAddress = "0xca843279e3427144cead5e4d5999a3d0";
  const seed = new Uint8Array([1]);

  expect(
    SupraAccount.getResourceAccountAddress(sourceAddress, seed).hex(),
  ).toBe("0xcbed05b37b6981a57f535c1f5d136734df822abaf4cd30c51c9b4d60eae79d5d");
});

test("Test getAddressFromAccountOrAddress", () => {
  const account = SupraAccount.fromSupraAccountObject(supraAccountObject);
  expect(
    getAddressFromAccountOrAddress(supraAccountObject.address!).toString(),
  ).toBe(supraAccountObject.address);
  expect(
    getAddressFromAccountOrAddress(
      HexString.ensure(supraAccountObject.address!),
    ).toString(),
  ).toBe(supraAccountObject.address);
  expect(getAddressFromAccountOrAddress(account).toString()).toBe(
    supraAccountObject.address,
  );
});

test("Gets the collection id", async () => {
  const creatorAddress =
    "0x28aa1624f8a8974c4158da696eea0e1c26af2cf7cacdb3564193ae817a44f908";
  const collectionName = "AliceCollection";
  expect(
    SupraAccount.getCollectionID(creatorAddress, collectionName).hex(),
  ).toBe("0x0524ffd0955d9c8c405315829ce896f5ced080cd15f146bbc690323d4d141b12");
});

describe("SupraAccount output excludes key material", () => {
  /**
   * Returns the encodings of `bytes` that are searched for in the output:
   * hex with and without `0x`, base64, and comma-separated decimal bytes.
   */
  function encodings(bytes: Uint8Array): string[] {
    const hex = Buffer.from(bytes).toString("hex");
    return [
      hex,
      `0x${hex}`,
      Buffer.from(bytes).toString("base64"),
      Array.from(bytes).join(","),
    ];
  }

  /**
   * Returns true if `output` contains any encoding of `bytes`. Decimal bytes are also matched
   * after removing everything except digit runs, so that padded or line-wrapped arrays match.
   */
  function containsBytes(output: string, bytes: Uint8Array): boolean {
    const digitRuns = (output.match(/\d+/g) ?? []).join(",");
    return encodings(bytes).some(
      (needle) => output.includes(needle) || digitRuns.includes(needle),
    );
  }

  const account = new SupraAccount();
  const { secretKey } = account.signingKey;
  const seed = secretKey.slice(0, 32);

  const outputs: [string, () => string][] = [
    ["JSON.stringify", () => JSON.stringify(account)],
    ["util.inspect", () => util.inspect(account)],
    [
      "util.inspect showHidden",
      () => util.inspect(account, { showHidden: true }),
    ],
    [
      "util.inspect showHidden, unlimited depth and array length",
      () =>
        util.inspect(account, {
          showHidden: true,
          depth: Infinity,
          maxArrayLength: Infinity,
          getters: true,
        }),
    ],
    ["console.log(account)", () => util.format(account)],
    ['console.log("%o", account)', () => util.format("%o", account)],
    ['console.log("%O", account)', () => util.format("%O", account)],
    ['console.log("%j", account)', () => util.format("%j", account)],
    ["object spread", () => util.inspect({ ...account }, { showHidden: true })],
  ];

  test("the search finds the key bytes in an output that contains them", () => {
    const leaky = util.inspect(account.signingKey, { showHidden: true });
    expect(containsBytes(leaky, seed)).toBe(true);
    expect(containsBytes(leaky, secretKey)).toBe(true);
    expect(
      containsBytes(account.toPrivateKeyObject().privateKeyHex, seed),
    ).toBe(true);
  });

  test.each(outputs)("%s contains no seed or secret key bytes", (_, render) => {
    const output = render();
    expect(containsBytes(output, seed)).toBe(false);
    expect(containsBytes(output, secretKey)).toBe(false);
  });

  test.each(outputs)("%s contains the address", (_, render) => {
    expect(render()).toContain(account.address().hex());
  });

  test("JSON.stringify returns the address and the public key", () => {
    expect(JSON.parse(JSON.stringify(account))).toEqual({
      address: account.address().hex(),
      publicKeyHex: account.pubKey().hex(),
    });
  });

  test("signingKey is not an enumerable own property", () => {
    expect(Object.keys(account)).not.toContain("signingKey");
    expect(
      Object.getOwnPropertyDescriptor(account, "signingKey")?.enumerable,
    ).toBe(false);
  });
});

describe("SupraAccount key access", () => {
  test("signingKey.publicKey and toPrivateKeyObject return the account's keys", () => {
    const account = SupraAccount.fromSupraAccountObject(supraAccountObject);
    expect(HexString.fromUint8Array(account.signingKey.publicKey).hex()).toBe(
      supraAccountObject.publicKeyHex,
    );
    expect(HexString.fromUint8Array(account.signingKey.secretKey).hex()).toBe(
      supraAccountObject.privateKeyHex,
    );
    expect(account.toPrivateKeyObject()).toEqual({
      address: supraAccountObject.address,
      publicKeyHex: supraAccountObject.publicKeyHex,
      privateKeyHex: supraAccountObject.privateKeyHex.slice(0, 66),
    });
  });

  test("signingKey.publicKey of a derived account matches the known public key", () => {
    const account = SupraAccount.fromDerivePath(
      "m/44'/637'/0'/0'/0'",
      mnemonic,
    );
    expect(HexString.fromUint8Array(account.signingKey.publicKey).hex()).toBe(
      "0xea526ba1710343d953461ff68641f1b7df5f23b9042ffa2d2a798d3adb3f3d6c",
    );
  });

  test("toPrivateKeyObject round-trips a generated account", () => {
    const a1 = new SupraAccount();
    const a2 = SupraAccount.fromSupraAccountObject(a1.toPrivateKeyObject());
    expect(a2.signingKey.secretKey).toEqual(a1.signingKey.secretKey);
    expect(a2.signingKey.publicKey).toEqual(a1.signingKey.publicKey);
    expect(a2.toPrivateKeyObject()).toEqual(a1.toPrivateKeyObject());
  });

  test("authKey is memoized", () => {
    const account = new SupraAccount();
    expect(account.authKey()).toBe(account.authKey());
    expect(account.authKey().hex()).toBe(account.address().hex());
  });
});

describe("SupraAccount.fromDerivePath mnemonic validation", () => {
  const path = "m/44'/637'/0'/0'/0'";
  const address =
    "0x07968dab936c1bad187c60ce4082f307d030d780e91e694ae03aef16aba73f30";

  test("throws for a 12-word phrase with a wrong checksum", () => {
    const words = mnemonic.split(" ");
    words[11] = "abandon";
    const phrase = words.join(" ");
    expect(words.every((word) => wordlist.includes(word))).toBe(true);
    expect(bip39.validateMnemonic(phrase, wordlist)).toBe(false);
    expect(() => SupraAccount.fromDerivePath(path, phrase)).toThrow(
      new Error("Invalid mnemonic"),
    );
  });

  test("throws for 12 words outside the wordlist", () => {
    const phrase = Array(12).fill("zzzz").join(" ");
    expect(() => SupraAccount.fromDerivePath(path, phrase)).toThrow(
      new Error("Invalid mnemonic"),
    );
  });

  test("throws for a word count that BIP-39 does not allow", () => {
    expect(() =>
      SupraAccount.fromDerivePath(
        path,
        mnemonic.split(" ").slice(0, 6).join(" "),
      ),
    ).toThrow(new Error("Invalid mnemonic"));
  });

  test("normalises whitespace and case before validation", () => {
    const phrase = `  ${mnemonic.toUpperCase().split(" ").join(" \t ")}\n`;
    expect(SupraAccount.fromDerivePath(path, phrase).address().hex()).toBe(
      address,
    );
  });

  test("derives the same account for a generated phrase each time", () => {
    const phrase = bip39.generateMnemonic(wordlist);
    const a1 = SupraAccount.fromDerivePath(path, phrase);
    const a2 = SupraAccount.fromDerivePath(path, phrase);
    expect(a1.address().hex()).toBe(a2.address().hex());
    expect(
      SupraAccount.fromDerivePath("m/44'/637'/1'/0'/0'", phrase)
        .address()
        .hex(),
    ).not.toBe(a1.address().hex());
  });
});
