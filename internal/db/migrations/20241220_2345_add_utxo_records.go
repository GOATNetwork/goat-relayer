package migrations

import (
	"time"

	"github.com/goatnetwork/goat-relayer/internal/models"
	"gorm.io/gorm"
)

func AddUtxoRecords(tx *gorm.DB) error {
	utxos := []models.Utxo{
		{
			ID:   1,
			Uid:  "",
			Txid: "ba7dc3e909686bc8cffa2757bba25338f14e281f449afd265d10ee9edb9811dc",
			PkScript: []byte{
				0x00, 0x14, 0x90, 0x34, 0xd0, 0xe5, 0xbc, 0xc8,
				0xe9, 0x6f, 0x6c, 0xbe, 0x89, 0xce, 0xa6, 0xe0,
				0x91, 0xae, 0xa9, 0x5d, 0xd9, 0xd8,
			},
			SubScript:     []byte{},
			OutIndex:      0,
			Amount:        50000,
			Receiver:      "bc1qjq6dpeduer5k7m973882dcy34654mkwcvgpr08",
			WalletVersion: "1",
			Sender:        "",
			EvmAddr:       "0x738fe7d89c172239bf456D387Ad2c60A79087917",
			Source:        "deposit",
			ReceiverType:  "P2WPKH",
			Status:        "processed",
			ReceiveBlock:  873517,
			SpentBlock:    0,
			UpdatedAt:     mustParseTime("2024-12-07 03:59:08.066994816+00:00"),
		},
		{
			ID:   2,
			Uid:  "",
			Txid: "a50246a76afc28ec6f1a6e535ddbb71e7d27358bc1f1fc1e60ae5647cc766354",
			PkScript: []byte{
				0x00, 0x14, 0x90, 0x34, 0xd0, 0xe5, 0xbc, 0xc8,
				0xe9, 0x6f, 0x6c, 0xbe, 0x89, 0xce, 0xa6, 0xe0,
				0x91, 0xae, 0xa9, 0x5d, 0xd9, 0xd8,
			},
			SubScript:     []byte{},
			OutIndex:      0,
			Amount:        50000,
			Receiver:      "bc1qjq6dpeduer5k7m973882dcy34654mkwcvgpr08",
			WalletVersion: "1",
			Sender:        "",
			EvmAddr:       "0x738fe7d89c172239bf456D387Ad2c60A79087917",
			Source:        "deposit",
			ReceiverType:  "P2WPKH",
			Status:        "processed",
			ReceiveBlock:  873518,
			SpentBlock:    0,
			UpdatedAt:     mustParseTime("2024-12-07 03:59:08.067945212+00:00"),
		},
		{
			ID:   3,
			Uid:  "",
			Txid: "2638a8f782ce703e59d06bb2f4b0c65153c141a2aa07f4b20df3a01f5d8a2462",
			PkScript: []byte{
				0x00, 0x14, 0x90, 0x34, 0xd0, 0xe5, 0xbc, 0xc8,
				0xe9, 0x6f, 0x6c, 0xbe, 0x89, 0xce, 0xa6, 0xe0,
				0x91, 0xae, 0xa9, 0x5d, 0xd9, 0xd8,
			},
			OutIndex:      0,
			Amount:        50000,
			Receiver:      "bc1qjq6dpeduer5k7m973882dcy34654mkwcvgpr08",
			WalletVersion: "1",
			Sender:        "",
			EvmAddr:       "0x738fe7d89c172239bf456D387Ad2c60A79087917",
			Source:        "deposit",
			ReceiverType:  "P2WPKH",
			Status:        "spent",
			ReceiveBlock:  873521,
			SpentBlock:    873752,
			UpdatedAt:     mustParseTime("2024-12-08 06:47:57.385513245+00:00"),
		},
		{
			ID:   4,
			Uid:  "",
			Txid: "451cae01882da59279fce894f9f57c5ae17f4ee10d924aab355de94e661287bc",
			PkScript: []byte{
				0x00, 0x14, 0x90, 0x34, 0xd0, 0xe5, 0xbc, 0xc8,
				0xe9, 0x6f, 0x6c, 0xbe, 0x89, 0xce, 0xa6, 0xe0,
				0x91, 0xae, 0xa9, 0x5d, 0xd9, 0xd8,
			},
			SubScript:     []byte{},
			OutIndex:      0,
			Amount:        50000,
			Receiver:      "bc1qjq6dpeduer5k7m973882dcy34654mkwcvgpr08",
			WalletVersion: "1",
			Sender:        "",
			EvmAddr:       "0x738fe7d89c172239bf456D387Ad2c60A79087917",
			Source:        "deposit",
			ReceiverType:  "P2WPKH",
			Status:        "spent",
			ReceiveBlock:  873586,
			SpentBlock:    873729,
			UpdatedAt:     mustParseTime("2024-12-08 02:16:34.799847784+00:00"),
		},
		{
			ID:   5,
			Uid:  "",
			Txid: "a01187bdcf4c3577d3057c8a6f59b7f9d410b600cc16e92e3d6a6b53815c1e3c",
			PkScript: []byte{
				0x00, 0x14, 0x90, 0x34, 0xd0, 0xe5, 0xbc, 0xc8,
				0xe9, 0x6f, 0x6c, 0xbe, 0x89, 0xce, 0xa6, 0xe0,
				0x91, 0xae, 0xa9, 0x5d, 0xd9, 0xd8,
			},
			SubScript:     []byte{},
			OutIndex:      0,
			Amount:        100000,
			Receiver:      "bc1qjq6dpeduer5k7m973882dcy34654mkwcvgpr08",
			WalletVersion: "1",
			EvmAddr:       "0x71A376962AA4A1245325857499324DA8Ede63c2d",
			Source:        "deposit",
			ReceiverType:  "P2WPKH",
			Status:        "processed",
			ReceiveBlock:  873597,
			SpentBlock:    0,
			UpdatedAt:     mustParseTime("2024-12-07 05:28:37.91917737+00:00"),
		},
		{
			ID:   6,
			Uid:  "",
			Txid: "5638324bad8f0443c7dc8f1a84a0ab108de24f110780d8b4fbc8a8ff80ba0516",
			PkScript: []byte{
				0x00, 0x20, 0xc9, 0x12, 0x52, 0x8d, 0x5d, 0xd9,
				0x83, 0x04, 0x0f, 0x14, 0xa0, 0xa2, 0x96, 0x34,
				0xca, 0xb3, 0x39, 0xf6, 0x19, 0x8a, 0xe9, 0xce,
				0x4f, 0xa9, 0x6f, 0x1f, 0xb1, 0xbb, 0x76, 0xb5,
				0x99, 0x3b,
			},
			SubScript: []byte{
				0x14, 0x2a, 0x10, 0x87, 0x74, 0x0b, 0xad, 0xcf,
				0xf4, 0x15, 0xfa, 0xa0, 0xb6, 0x37, 0x9f, 0x12,
				0xfa, 0x76, 0x28, 0xd3, 0x97, 0x75, 0x21, 0x03,
				0xce, 0x99, 0xe6, 0xa2, 0x50, 0xa7, 0x20, 0x25,
				0x1c, 0x05, 0xa0, 0x21, 0x01, 0x9f, 0x89, 0x4c,
				0xf6, 0x39, 0xf6, 0x53, 0xd5, 0x1e, 0x9b, 0x05,
				0xe3, 0xcf, 0xc0, 0x4c, 0x88, 0xee, 0x9b, 0x5d,
				0xac,
			},
			OutIndex:      0,
			Amount:        600000,
			Receiver:      "bc1qeyf99r2amxpsgrc55z3fvdx2kvulvxv2a88yl2t0r7cmka44nyasnzrkkz",
			WalletVersion: "1",
			Sender:        "",
			EvmAddr:       "2a1087740badcff415faa0b6379f12fa7628d397",
			Source:        "deposit",
			ReceiverType:  "P2WSH",
			Status:        "spent",
			ReceiveBlock:  873605,
			SpentBlock:    873729,
			UpdatedAt:     mustParseTime("2024-12-08 02:16:34.799680002+00:00"),
		},
		{
			ID:   7,
			Uid:  "",
			Txid: "6691c00f6f33434ae75f1e73f6d7dcfddcfa6075cabcc4add6ff7411f1d85522",
			PkScript: []byte{
				0x00, 0x20, 0xfc, 0x96, 0xa0, 0x5f, 0x3c, 0x64,
				0x17, 0xb3, 0x35, 0xeb, 0x8d, 0x32, 0xdc, 0x83,
				0x6b, 0x92, 0x54, 0x1e, 0xb4, 0x68, 0x30, 0x51,
				0xa6, 0x72, 0x56, 0x47, 0x59, 0x0c, 0x90, 0xdc,
				0xcc, 0xc5,
			},
			SubScript: []byte{
				0x14, 0x71, 0xa3, 0x76, 0x96, 0x2a, 0xa4, 0xa1,
				0x24, 0x53, 0x25, 0x85, 0x74, 0x99, 0x32, 0x4d,
				0xa8, 0xed, 0xe6, 0x3c, 0x2d, 0x75, 0x21, 0x03,
				0xce, 0x99, 0xe6, 0xa2, 0x50, 0xa7, 0x20, 0x25,
				0x1c, 0x05, 0xa0, 0x21, 0x01, 0x9f, 0x89, 0x4c,
				0xf6, 0x39, 0xf6, 0x53, 0xd5, 0x1e, 0x9b, 0x05,
				0xe3, 0xcf, 0xc0, 0x4c, 0x88, 0xee, 0x9b, 0x5d,
				0xac,
			},
			Amount:        5000000,
			Receiver:      "bc1qljt2qheuvstmxd0t35edeqmtjf2padrgxpg6vujkgavseyxuenzspuq6k9",
			WalletVersion: "1",
			Sender:        "",
			EvmAddr:       "71a376962aa4a1245325857499324da8ede63c2d",
			Source:        "deposit",
			ReceiverType:  "P2WSH",
			Status:        "processed",
			ReceiveBlock:  873605,
			SpentBlock:    0,
			UpdatedAt:     mustParseTime("2024-12-07 06:33:35.134420733+00:00"),
		},
		{
			ID:   8,
			Uid:  "",
			Txid: "8cfe59be227428f7635bac5b07437be2b4a497f77b2be9a00db07bbe98f0ea42",
			PkScript: []byte{
				0x00, 0x14, 0x90, 0x34, 0xd0, 0xe5, 0xbc, 0xc8,
				0xe9, 0x6f, 0x6c, 0xbe, 0x89, 0xce, 0xa6, 0xe0,
				0x91, 0xae, 0xa9, 0x5d, 0xd9, 0xd8,
			},
			SubScript:     []byte{},
			OutIndex:      1,
			Amount:        447149,
			Receiver:      "bc1qjq6dpeduer5k7m973882dcy34654mkwcvgpr08",
			WalletVersion: "1",
			Sender:        "",
			Source:        "withdrawal",
			ReceiverType:  "P2WPKH",
			Status:        "spent",
			ReceiveBlock:  873729,
			SpentBlock:    873752,
			UpdatedAt:     mustParseTime("2024-12-08 06:47:57.385324561+00:00"),
		},
		{
			ID:   9,
			Uid:  "",
			Txid: "65d6d11ba8eb434e8cf30accabca1ca8c1d1868ce8d0561ffa51bcf3ceb4db2d",
			PkScript: []byte{
				0x00, 0x14, 0x90, 0x34, 0xd0, 0xe5, 0xbc, 0xc8,
				0xe9, 0x6f, 0x6c, 0xbe, 0x89, 0xce, 0xa6, 0xe0,
				0x91, 0xae, 0xa9, 0x5d, 0xd9, 0xd8,
			},
			SubScript:     []byte{},
			OutIndex:      1,
			Amount:        282558,
			Receiver:      "bc1qjq6dpeduer5k7m973882dcy34654mkwcvgpr08",
			WalletVersion: "1",
			Sender:        "",
			Source:        "withdrawal",
			ReceiverType:  "P2WPKH",
			Status:        "processed",
			ReceiveBlock:  873752,
			SpentBlock:    0,
			UpdatedAt:     mustParseTime("2024-12-08 06:35:10.394338948+00:00"),
		},
		{
			ID:   10,
			Uid:  "",
			Txid: "01ae742b31828c30f333b5cc4c16ba6ee785f805d150f77eadc72e41bf4765f4",
			PkScript: []byte{
				0x00, 0x14, 0x90, 0x34, 0xd0, 0xe5, 0xbc, 0xc8,
				0xe9, 0x6f, 0x6c, 0xbe, 0x89, 0xce, 0xa6, 0xe0,
				0x91, 0xae, 0xa9, 0x5d, 0xd9, 0xd8,
			},
			SubScript:     []byte{},
			OutIndex:      0,
			Amount:        100000,
			Receiver:      "bc1qjq6dpeduer5k7m973882dcy34654mkwcvgpr08",
			WalletVersion: "1",
			Sender:        "",
			EvmAddr:       "0x5Bb093d8870727B51e1746Af83984291f41e8A4b",
			Source:        "deposit",
			ReceiverType:  "P2WPKH",
			Status:        "processed",
			ReceiveBlock:  874914,
			SpentBlock:    0,
			UpdatedAt:     mustParseTime("2024-12-15 22:11:19.829573917+00:00"),
		},
		{
			ID:   11,
			Uid:  "",
			Txid: "361d1b189d40bff5de133fee3619d3f8e6a53cf5734a7188f30161fc6072c80e",
			PkScript: []byte{
				0x00, 0x14, 0x90, 0x34, 0xd0, 0xe5, 0xbc, 0xc8,
				0xe9, 0x6f, 0x6c, 0xbe, 0x89, 0xce, 0xa6, 0xe0,
				0x91, 0xae, 0xa9, 0x5d, 0xd9, 0xd8,
			},
			SubScript:     []byte{},
			OutIndex:      0,
			Amount:        4100000,
			Receiver:      "bc1qjq6dpeduer5k7m973882dcy34654mkwcvgpr08",
			WalletVersion: "1",
			Sender:        "",
			EvmAddr:       "0x5Bb093d8870727B51e1746Af83984291f41e8A4b",
			Source:        "deposit",
			ReceiverType:  "P2WPKH",
			Status:        "processed",
			ReceiveBlock:  875187,
			SpentBlock:    0,
			UpdatedAt:     mustParseTime("2024-12-17 19:27:24.719701515+00:00"),
		},
		{
			ID:   12,
			Uid:  "",
			Txid: "ac020d14fd004331d5590aa5a1e6ca9f0ddd5de161e5440a9810f3910d81712a",
			PkScript: []byte{
				0x00, 0x14, 0x90, 0x34, 0xd0, 0xe5, 0xbc, 0xc8,
				0xe9, 0x6f, 0x6c, 0xbe, 0x89, 0xce, 0xa6, 0xe0,
				0x91, 0xae, 0xa9, 0x5d, 0xd9, 0xd8,
			},
			SubScript:     []byte{},
			OutIndex:      0,
			Amount:        500000,
			Receiver:      "bc1qjq6dpeduer5k7m973882dcy34654mkwcvgpr08",
			WalletVersion: "1",
			Sender:        "",
			EvmAddr:       "0xBB3Da31029cd22BCeC9615322c43663741b510FD",
			Source:        "deposit",
			ReceiverType:  "P2WPKH",
			Status:        "processed",
			ReceiveBlock:  875281,
			SpentBlock:    0,
			UpdatedAt:     mustParseTime("2024-12-18 10:05:29.73030734+00:00"),
		},
	}

	return tx.Create(&utxos).Error
}

func mustParseTime(value string) time.Time {
	t, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", value)
	if err != nil {
		panic(err)
	}
	return t
}
