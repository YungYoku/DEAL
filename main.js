const ipTable = [
	0, 32, 64, 96, 1, 33, 65, 97,
	2, 34, 66, 98, 3, 35, 67, 99,
	4, 36, 68, 100, 5, 37, 69, 101,
	6, 38, 70, 102, 7, 39, 71, 103,
	8, 40, 72, 104, 9, 41, 73, 105,
	10, 42, 74, 106, 11, 43, 75, 107,
	12, 44, 76, 108, 13, 45, 77, 109,
	14, 46, 78, 110, 15, 47, 79, 111,
	16, 48, 80, 112, 17, 49, 81, 113,
	18, 50, 82, 114, 19, 51, 83, 115,
	20, 52, 84, 116, 21, 53, 85, 117,
	22, 54, 86, 118, 23, 55, 87, 119,
	24, 56, 88, 120, 25, 57, 89, 121,
	26, 58, 90, 122, 27, 59, 91, 123,
	28, 60, 92, 124, 29, 61, 93, 125,
	30, 62, 94, 126, 31, 63, 95, 127
];

const E = [
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
	24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
	36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
	48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
	60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71,
	72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83,
	84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
	96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
	108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
	120, 121, 122, 123, 124, 125, 126, 127, 108, 109, 110, 111,
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
	24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
	36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
	48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
	60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71,
]

const PBox = [
	10, 42, 74, 106, 11, 43, 75, 107,
	4, 36, 68, 100, 5, 37, 69, 101,
	6, 38, 70, 102, 7, 39, 71, 103,
	8, 40, 72, 104, 9, 41, 73, 105,
	22, 54, 86, 118, 23, 55, 87, 119,
	24, 56, 88, 120, 25, 57, 89, 121,
	30, 62, 94, 126, 31, 63, 95, 127,
	16, 48, 80, 112, 17, 49, 81, 113,
	12, 44, 76, 108, 13, 45, 77, 109,
	14, 46, 78, 110, 15, 47, 79, 111,
	0, 32, 64, 96, 1, 33, 65, 97,
	18, 50, 82, 114, 19, 51, 83, 115,
	20, 52, 84, 116, 21, 53, 85, 117,
	2, 34, 66, 98, 3, 35, 67, 99,
	28, 60, 92, 124, 29, 61, 93, 125,
	26, 58, 90, 122, 27, 59, 91, 123,
];

const sBoxDEAL = [
	[
		139, 220, 245, 162, 153, 5, 241, 25, 109, 18, 63, 225, 227, 41, 239, 166
	],
	[
		1, 95, 188, 94, 172, 234, 36, 0, 214, 24, 33, 233, 187, 132, 83, 144
	],
	[
		102, 35, 14, 74, 44, 92, 169, 13, 150, 212, 61, 202, 177, 122, 151, 238
	],
	[
		107, 137, 31, 87, 20, 6, 235, 197, 17, 163, 59, 228, 100, 49, 125, 174
	],
	[
		194, 67, 52, 221, 180, 81, 252, 37, 198, 45, 110, 203, 115, 104, 78, 121
	],
	[
		179, 129, 215, 155, 148, 91, 56, 120, 160, 143, 51, 50, 158, 73, 219, 145
	],
	[
		201, 211, 154, 159, 131, 114, 224, 118, 113, 97, 46, 12, 255, 64, 205, 229
	],
	[
		192, 200, 146, 196, 19, 183, 167, 175, 22, 57, 15, 130, 42, 93, 66, 190
	],
	[
		135, 68, 11, 86, 209, 152, 106, 164, 223, 249, 181, 82, 84, 10, 157, 38
	],
	[
		168, 58, 101, 124, 184, 23, 195, 99, 136, 123, 111, 173, 26, 75, 88, 206
	],
	[
		40, 79, 149, 48, 165, 244, 119, 213, 112, 204, 32, 208, 8, 242, 34, 218
	],
	[
		134, 39, 77, 89, 217, 251, 248, 127, 72, 71, 189, 54, 62, 117, 171, 250
	],
	[
		103, 226, 105, 53, 191, 47, 253, 60, 182, 222, 9, 236, 3, 161, 240, 170
	],
	[
		16, 231, 254, 178, 76, 133, 243, 80, 176, 185, 232, 96, 140, 116, 85, 55
	],
	[
		21, 98, 90, 147, 4, 30, 237, 65, 141, 193, 28, 142, 43, 108, 186, 2
	],
	[
		230, 70, 156, 199, 7, 126, 128, 216, 207, 246, 138, 247, 69, 29, 27, 210
	]
]

function expand(layerData, isDecrypt = false) {
	const block = layerData.split('')

	if (isDecrypt) {
		return block.join('')
	}

	const expandedBlock = [...E]
	expandedBlock.forEach((item, index) => {
		expandedBlock[index] = block[item]
	})

	return expandedBlock.join('')
}

// Реализации подстановки для S-бокса
function substitution(layerData, isDecrypt = false) {
	const block = layerData.split('')

	const subBlocks = []
	for (let i = 0; i < block.length; i += 8) {
		subBlocks.push([])
	}

	let i = 0
	for (let j = 0; j < block.length; j++) {
		if (j % 8 === 0 && j > 0) i++
		subBlocks[i].push(block[j])
	}

	if (isDecrypt) {
		for (let k = 0; k < subBlocks.length; k++) {
			const subBlock = subBlocks[k]

			if (subBlock.includes('8') || subBlock.includes('9')) {
				subBlocks[k] = subBlocks[k].join('')
				continue
			}

			for (let i = 0; i < sBoxDEAL.length; i++) {
				for (let j = 0; j < sBoxDEAL[i].length; j++) {
					if (sBoxDEAL[i][j].toString(2).padStart(8, '0') === subBlock.join('')) {
						subBlocks[k] = i.toString(2).padStart(4, '0') + j.toString(2).padStart(4, '0')
					}
				}
			}
		}
	} else {
		for (let k = 0; k < subBlocks.length; k++) {
			const subBlock = subBlocks[k]

			if (subBlock.includes('8') || subBlock.includes('9')) {
				subBlocks[k] = subBlocks[k].join('')
				continue
			}

			const row = parseInt(subBlock.slice(0, 4).join(''), 2)
			const col = parseInt(subBlock.slice(4, 8).join(''), 2)
			const outputValue = sBoxDEAL[row][col];

			subBlocks[k] = outputValue.toString(2).padStart(8, '0')
		}
	}

	return subBlocks.join('')
}

// Реализации перестановки для P-бокса
function permutation(layerData, isDecrypt = false) {
	const block = layerData.split('')

	if (isDecrypt) {
		const reversePBox = new Array(PBox.length);
		for (let i = 0; i < PBox.length; i++) {
			reversePBox[PBox[i]] = i;
		}
		return reversePBox.map(index => block[index]).join('');
	}

	return PBox.map(index => block[index]).join('');
}

function generateRoundKey(previousKey, roundNumber, isDecrypt = false) {
	const keySize = previousKey.length;

	// Сжатие и перестановка для генерации следующего ключа
	const compressedKey = previousKey.split('').map((bit, index) => {
		const newIndex = (index + roundNumber + bit) % keySize;
		return previousKey[newIndex] ^ (index % 2); // Сжатие: XOR с битами по четности
	});

	// Для дешифрования инвертируем порядок бит в ключе
	if (isDecrypt) {
		return compressedKey.reverse().join('');
	}

	return compressedKey.join('');
}

function xor(a, b) {
	return a.split('').map((bit, i) => bit ^ b[i]).join('');
}

function initialPermutation(layerData, isDecrypt = false) {
	const block = layerData.split('')

	// Для дешифрования меняем порядок битов в таблице
	if (isDecrypt) {
		const reverseIpTable = new Array(ipTable.length);
		for (let i = 0; i < ipTable.length; i++) {
			reverseIpTable[ipTable[i]] = i;
		}
		return reverseIpTable.map(index => block[index]).join('');
	}

	// Для шифрования применяем перестановку битов
	return ipTable.map(index => block[index]).join('');
}

function dealEncrypt(block, key, vector) {
	const roundsAmount = 8

	const startKey = key
	const keys = []
	for (let i = 0; i < roundsAmount; i++) {
		const currentKey = i === 0 ? startKey : keys[i - 1]
		keys.push(generateRoundKey(currentKey, i))
	}
	console.log('block before IP', block)
	let currentBlock = initialPermutation(block)
	console.log('block after IP', currentBlock)

	currentBlock = xor(currentBlock, vector)

	let left = ''
	let right = ''

	for (let i = 0; i < roundsAmount; i++) {
		left = currentBlock.split('').splice(0, currentBlock.length / 2).join('')
		right = currentBlock.split('').splice(currentBlock.length / 2, currentBlock.length).join('')

		console.log('key', key)
		const currentRight = right
		right = xor(right, keys[i])
		right = xor(right, left)
		left = currentRight

		currentBlock = left + right
		console.log('right part + key + xor with left', currentBlock)

		currentBlock = substitution(currentBlock)
		console.log('block after substitution', currentBlock)
		currentBlock = permutation(currentBlock)
		console.log('block after permutation', currentBlock)
	}

	return permutation(currentBlock)
}

function dealDecrypt(block, key, vector) {
	const roundsAmount = 8

	const startKey = key
	const keys = []
	for (let i = 0; i < roundsAmount; i++) {
		const currentKey = i === 0 ? startKey : keys[i - 1]
		keys.push(generateRoundKey(currentKey, i))
	}
	let currentBlock = permutation(block, true)

	let left = ''
	let right = ''

	for (let i = roundsAmount; i > 0; i--) {
		currentBlock = permutation(currentBlock, true)
		currentBlock = substitution(currentBlock, true)

		left = currentBlock.split('').splice(0, currentBlock.length / 2).join('')
		right = currentBlock.split('').splice(currentBlock.length / 2, currentBlock.length).join('')

		const currentLeft = left
		left = xor(left, keys[i - 1])
		left = xor(left, right)
		right = currentLeft

		currentBlock = left + right
	}

	currentBlock = xor(currentBlock, vector)

	return initialPermutation(currentBlock, true)
}

// Функция дополнения блока
function padBlock(block, blockSize) {
	let newBlock = block.split('')
	for (let i = 0; i < newBlock.length; i++) {
		if (newBlock[i] === ' ') {
			newBlock[i] = 9;
		}
	}

	for (let i = 0; newBlock.length < blockSize; i++) {
		newBlock.push(...[0, 0, 1, 0, 0, 0, 0, 0]);
	}
	return newBlock.join('');
}

// Функция удаления дополнения блока
function unpadBlock(block) {
	let unpadedBlock = ''
	for (let i = 0; i < block.length; i++) {
		if (+block[i] === 9) {
			unpadedBlock += ' ';
		} else {
			unpadedBlock += block[i];
		}
	}
	return unpadedBlock.replace(/\s/g, "")
}

// Преобразование строки в бинарную форму
function stringToBinary(str) {
	return str.split('').map(char => char.charCodeAt(0).toString(2).padStart(8, '0')).join('');
}

// Преобразование бинарной строки в base64
function binaryToBase64(binary) {
	const bytes = binary.match(/.{1,8}/g).map(byte => parseInt(byte, 2));
	return btoa(String.fromCharCode(...bytes));
}

function base64ToBinary(base64) {
	const decodedString = atob(base64);
	let binary = "";
	for (let i = 0; i < decodedString.length; i++) {
		const charCode = decodedString.charCodeAt(i).toString(2);
		binary += "0".repeat(8 - charCode.length) + charCode;
	}
	return binary;
}

// Преобразование бинарной строки в обычную строку
function binaryToString(binary) {
	return binary.match(/.{1,8}/g).map(byte => String.fromCharCode(parseInt(byte, 2))).join('');
}

// Пример использования
const encryptionKey = document.querySelector('.encryption-key')
const encryptionInitializationVector = document.querySelector('.encryption-initialization-vector')
const messageInput = document.querySelector('.message-input')
const encryptedMessage = document.querySelector('.encrypted-message')
const encryptButton = document.querySelector('.encrypt-button')
const decryptionKey = document.querySelector('.decryption-key')
const decryptionInitializationVector = document.querySelector('.decryption-initialization-vector')
const encryptedMessageInput = document.querySelector('.encrypted-message-input')
const decryptedMessage = document.querySelector('.decrypted-message')
const decryptButton = document.querySelector('.decrypt-button')
encryptButton.addEventListener('click', encrypt)
decryptButton.addEventListener('click', decrypt)
let key = '';
let initializationVector = '';

// Шифрование
function encrypt() {
	key = encryptionKey.value;
	initializationVector = encryptionInitializationVector.value;
	const plaintext = messageInput.value;
	const binaryPlaintext = stringToBinary(plaintext);

	const blockSize = key.length;
	const blocks = [];
	const encryptedBlocks = [];
	let vector = initializationVector

	for (let i = 0; i < binaryPlaintext.length; i += blockSize) {
		let block = binaryPlaintext.slice(i, i + blockSize);
		blocks.push(block);
	}

	for (let i = 0; i < blocks.length; i++) {
		let block = blocks[i];
		if (block.length < blockSize) {
			block = padBlock(block, blockSize);
		}
		const encryptedBlock = dealEncrypt(block, key, vector);
		encryptedBlocks.push(encryptedBlock);

		vector = encryptedBlock
	}
	const encryptedPlaintext = binaryToBase64(encryptedBlocks.join(''));

	// Вывод результатов
	encryptedMessage.innerHTML = `Зашифрованное: ${encryptedPlaintext}`
}

// Дешифрование
let decryptedPlaintext = null

function decrypt() {
	key = decryptionKey.value;
	initializationVector = decryptionInitializationVector.value;
	const plaintext = encryptedMessageInput.value;
	const binaryPlaintext = base64ToBinary(plaintext);

	const blockSize = key.length;
	const blocks = [];
	const decryptedBlocks = [];
	let vector = initializationVector

	for (let i = 0; i < binaryPlaintext.length; i += blockSize) {
		let block = binaryPlaintext.slice(i, i + blockSize);
		blocks.push(block);
	}

	for (let i = blocks.length - 1; i >= 0; i--) {
		const encryptedBlock = blocks[i];

		if (i <= 0) vector = initializationVector
		else vector = blocks[i - 1]

		let decryptedBlock = dealDecrypt(encryptedBlock, key, vector);
		if (i === blocks.length - 1) {
			decryptedBlock = unpadBlock(decryptedBlock)
		}
		decryptedBlocks.push(decryptedBlock);
	}
	decryptedPlaintext = binaryToString(decryptedBlocks.reverse().join(''));

	// Вывод результатов
	decryptedMessage.innerHTML = `Расшифрованное: ${decryptedPlaintext}`
}
