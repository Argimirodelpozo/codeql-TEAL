# Code automatically generated - DO NOT EDIT.

import typing

import algopy as py
from algopy import logicsig, subroutine, BigUInt, Bytes, arc4, UInt64, urange
from algopy.arc4 import UInt256, DynamicArray
from algopy.op import bzero, sha256, EllipticCurve as ec, EC, setbit_bytes

#################### Curve parameters #################

# curve order
R_MOD = 52435875175126190479447740508185965837690552500527637822603658699938581184513

# field order
P_MOD = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787

#################### Trusted setup ####################

G2_SRS_0_X_0 = 3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758
G2_SRS_0_X_1 = 352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160
G2_SRS_0_Y_0 = 927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582
G2_SRS_0_Y_1 = 1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905

G2_SRS_1_X_0 = 2438727288797112005158916266475775093733288980101109719723144662515784844861846663745236242880804891772120557953654
G2_SRS_1_X_1 = 2412063939812864948466857382307910192623752651189579809662512915748139344582431904202664943823675754241567991545160
G2_SRS_1_Y_0 = 1400847362443033576064313261617377228036663947392061839935534316030304409490651017578354899837464813680972243503163
G2_SRS_1_Y_1 = 1324508598293751865620769923819606212655344979502990727026340277924826793028556110121771375479450421588931922656397

G1_SRS_X = 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507
G1_SRS_Y = 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569

########################################################

@logicsig(name="Verifier")
def verify() -> bool:
	"""Verify the proof for the given public inputs.
	   Fail if the proof is invalid"""

	q = BigUInt(R_MOD)

	# read proof and public inputs
	# they are passed in to an arc4 contract as DyanmicArray[Bytes32]
	# where Bytes32 is a 32 bytes StaticArray; so we skip the first 2 bytes which encode
	# the length of the array (we also skip the first app arg which is the method name)
	proof = py.Txn.application_args(1)[2:]
	public_inputs = py.Txn.application_args(2)[2:]

	# check proof and public inputs lengths
	assert proof.length == 33 * 32
	assert public_inputs.length == 2 * 32

	### Read verifying key ###
	VK_NB_PUBLIC_INPUTS = UInt64(2)
	VK_DOMAIN_SIZE = BigUInt(8)
	VK_INV_DOMAIN_SIZE = BigUInt(45881390778235416669516772944662720107979233437961683094778201362446258536449)
	VK_OMEGA = BigUInt(23674694431658770659612952115660802947967373701506253797663184111817857449850)

	VK_QL = Bytes.from_hex("0f4dc4f6a3c2f38b5a0d57995ca2b422c9b772ed630e84280405953a3ef835bfc06fbf403adc531524acfa5b91cf56bd071749df4c3436c74ec8bcb6cb32f7d5583da31ad664a043af5d85a3844009add356cbbf6816c29d69beb22dc0cd5410")
	VK_QR = Bytes.from_hex("04e247e860248c69f9edc8b3a7bc85689bf9fc8fd29a85871900aec78181b83527c425440ee11752c8b08d6c232ae3ee17ee9b5f0090271051be4e7818d707d77427b77c055aea802e2162bc5a442e363dbeafd36b79549eacf85bd20b283cee")
	VK_QO = Bytes.from_hex("00f770f4599678c0ae8082f97ca59d0efb3d1d8b74a18447bb132b5318c4ec470ae4f7138ca9ff4bb5d13e96623625270b38ba79b98bb09decc8ff5772c2d8b4c55b33cc14cb0456551484d1dd8ec19cd2b5f1a838963599d2714a2f9d2906f8")
	VK_QM = Bytes.from_hex("0b38005f645c709626003c521bd0c5921d6e0bc7d22632499468d603472dc0de4cc28e7961a869caae93eaea6b00de9a0e287de527c44a1bebbe308c7bd51f7e8e2e8a6a15b52252691cc9cfa730e36360cc8398aa97d644758337f5d89e2378")
	VK_QK = Bytes.from_hex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

	VK_S1 = Bytes.from_hex("02d13aee87876961457d1d35e934e4dd50b359859bac54ecf654ab13d7c8cb73f7ee16b7b6dfd8587309d195ba4bf0a40f60cc8e01b9159dc9c64438fda713714895ee5f4499f54197bed47d1628188cd3bf403702220458d7a439f9f7f6d307")
	VK_S2 = Bytes.from_hex("00762ebe9fadbdef3c4be5f2b09c968e4880cc3b3f865948b8699b4ba22f53f3cbaf781f64df7daaa3bd72b50b4c860e0b6142cc073969ddde5afa08d07197083a5f4a24c0291c7930e403afb9fc01300851f256a79a719de14148638ad90d1d")
	VK_S3 = Bytes.from_hex("0217e277d392d10946691d51143883cfa0552ac351898f52d159c6c1efb21e733aaf4afd437deb8d99ef6462c6ac9db018b7480ca8a96c49c273f0d8e6c633a8f9bad57c55f9d9433e4465670e231b44601cff9466d0bbbb1e856c8cd2d3f2cc")
	
	VK_COSET_SHIFT = BigUInt(7)

	# Read the fiat-shamir values of the verifying key to match gnark's encoding of the point at infinity
	VK_QL_fs = Bytes.from_hex("0f4dc4f6a3c2f38b5a0d57995ca2b422c9b772ed630e84280405953a3ef835bfc06fbf403adc531524acfa5b91cf56bd071749df4c3436c74ec8bcb6cb32f7d5583da31ad664a043af5d85a3844009add356cbbf6816c29d69beb22dc0cd5410")
	VK_QR_fs = Bytes.from_hex("04e247e860248c69f9edc8b3a7bc85689bf9fc8fd29a85871900aec78181b83527c425440ee11752c8b08d6c232ae3ee17ee9b5f0090271051be4e7818d707d77427b77c055aea802e2162bc5a442e363dbeafd36b79549eacf85bd20b283cee")
	VK_QO_fs = Bytes.from_hex("00f770f4599678c0ae8082f97ca59d0efb3d1d8b74a18447bb132b5318c4ec470ae4f7138ca9ff4bb5d13e96623625270b38ba79b98bb09decc8ff5772c2d8b4c55b33cc14cb0456551484d1dd8ec19cd2b5f1a838963599d2714a2f9d2906f8")
	VK_QM_fs = Bytes.from_hex("0b38005f645c709626003c521bd0c5921d6e0bc7d22632499468d603472dc0de4cc28e7961a869caae93eaea6b00de9a0e287de527c44a1bebbe308c7bd51f7e8e2e8a6a15b52252691cc9cfa730e36360cc8398aa97d644758337f5d89e2378")
	VK_QK_fs = Bytes.from_hex("400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	
	VK_S1_fs = Bytes.from_hex("02d13aee87876961457d1d35e934e4dd50b359859bac54ecf654ab13d7c8cb73f7ee16b7b6dfd8587309d195ba4bf0a40f60cc8e01b9159dc9c64438fda713714895ee5f4499f54197bed47d1628188cd3bf403702220458d7a439f9f7f6d307")
	
	VK_S2_fs = Bytes.from_hex("00762ebe9fadbdef3c4be5f2b09c968e4880cc3b3f865948b8699b4ba22f53f3cbaf781f64df7daaa3bd72b50b4c860e0b6142cc073969ddde5afa08d07197083a5f4a24c0291c7930e403afb9fc01300851f256a79a719de14148638ad90d1d")
	
	VK_S3_fs = Bytes.from_hex("0217e277d392d10946691d51143883cfa0552ac351898f52d159c6c1efb21e733aaf4afd437deb8d99ef6462c6ac9db018b7480ca8a96c49c273f0d8e6c633a8f9bad57c55f9d9433e4465670e231b44601cff9466d0bbbb1e856c8cd2d3f2cc")
	

	# Read proof #
	# wires commitments
	L_COM = proof[0:96]
	R_COM = proof[96:192]
	O_COM = proof[192:288]

	# h = h_0 + x^{n+2}h_1 + x^{2(n+2)}h_2
	H_0 = proof[288:384]
	H_1 = proof[384:480]
	H_2 = proof[480:576]


	# wire values at zeta
	L_AT_Z = proof[576:608]
	R_AT_Z = proof[608:640]
	O_AT_Z = proof[640:672]

	S1_AT_Z = proof[672:704]  					# s1(zeta)
	S2_AT_Z = proof[704:736]  					# s2(zeta))
	GRAND_PRODUCT = proof[736:832]				# z(x)
	GRAND_PRODUCT_AT_Z_OMEGA = proof[832:864]   # z(w*zeta)

	# folded proof for opening of linear poly, l, r, o, s1, s2
	BATCH_OPENING_AT_Z = proof[864:960]

	# opening at zeta * omega
	OPENING_AT_Z_OMEGA = proof[960:1056]

	### check proof public inputs are well-formed ###
	if (BigUInt.from_bytes(L_AT_Z) >= q
			or BigUInt.from_bytes(R_AT_Z) >= q
			or BigUInt.from_bytes(O_AT_Z) >= q
			or BigUInt.from_bytes(S1_AT_Z) >= q
			or BigUInt.from_bytes(S2_AT_Z) >= q
			or BigUInt.from_bytes(GRAND_PRODUCT_AT_Z_OMEGA) >= q
	):
		return False

	for i in urange(VK_NB_PUBLIC_INPUTS):
		if BigUInt.from_bytes(public_inputs[i*32:(i+1)*32]) >= q:
			return False


	# Compute the fiat-shamir challenges as the prover (gnark).
	# After deriving all challenges, we need to make them modulo R_MOD

	gamma_pre = sha256(b'gamma' + VK_S1_fs + VK_S2_fs + VK_S3_fs + VK_QL_fs
					+ VK_QR_fs + VK_QM_fs + VK_QO_fs + VK_QK_fs + public_inputs
					+ fs(L_COM) + fs(R_COM) + fs(O_COM))
	beta_pre = sha256(b'beta' + gamma_pre)
	alpha_pre = sha256(b'alpha' + beta_pre + fs(GRAND_PRODUCT))
	zeta_pre = sha256(b'zeta' + alpha_pre + fs(H_0) + fs(H_1) + fs(H_2))

	gamma = curvemod(gamma_pre)
	beta = curvemod(beta_pre)
	alpha = curvemod(alpha_pre)
	zeta = curvemod(zeta_pre)

	# Zz is eval of Xⁿ-1 at zeta
	Zz = (expmod(zeta, VK_DOMAIN_SIZE, q) + q - BigUInt(1)) % q

	# zn is Zz * 1/n
	zn = (Zz * VK_INV_DOMAIN_SIZE) % q

	# Let's prepare to interpolate the public inputs
	w_ = BigUInt(1)
	batch = DynamicArray[UInt256]()
	for i in urange(VK_NB_PUBLIC_INPUTS):
		x = (zeta + q - w_) % q
		batch.append(UInt256(x))
		w_ = (w_ * VK_OMEGA) % q

	# Compute batch inversion
	temp = DynamicArray[UInt256]()
	prev = BigUInt(1)
	temp.append(UInt256(prev))
	for x256 in batch:
		x = BigUInt.from_bytes(x256.bytes)
		y = (x * prev) % q
		temp.append(UInt256(y))
		prev = y
	inv = expmod(prev, q - BigUInt(2), q)
	i = VK_NB_PUBLIC_INPUTS
	while i > 0:
		tmp = BigUInt.from_bytes(batch[i-1].bytes)
		cur = (inv * BigUInt.from_bytes(temp[i-1].bytes)) % q
		batch[i-1] = UInt256(cur)
		inv = (inv * tmp) % q
		i -= 1

	# We can now interpolate the public inputs (PI)
	w_ = BigUInt(1)
	for i in urange(VK_NB_PUBLIC_INPUTS):
		batch[i] = UInt256((w_ * ((BigUInt.from_bytes(batch[i].bytes) * zn)
							% q)) % q)
		w_ = (w_ * VK_OMEGA) % q

	tmp = BigUInt(0)
	PI = BigUInt(0)
	for i in urange(VK_NB_PUBLIC_INPUTS):
		tmp = (BigUInt.from_bytes(batch[i].bytes)
				* BigUInt.from_bytes(public_inputs[i*32:(i+1)*32])) % q
		PI = (PI + tmp) % q

	# compute alpha2Lagrange: alpha**2 * (z**n - 1) / (z - 1)
	res = (zeta + q - BigUInt(1)) % q
	res = expmod(res, q - BigUInt(2), q)
	res = (res * zn) % q
	res = (res * alpha) % q
	res = (res * alpha) % q
	alpha2Lagrange = res

	# verify opening linearization polynomial
	s1 = (BigUInt.from_bytes(S1_AT_Z) * beta) % q
	s1 = (s1 + gamma + BigUInt.from_bytes(L_AT_Z)) % q

	s2 = (BigUInt.from_bytes(S2_AT_Z) * beta) % q
	s2 = (s2 + gamma + BigUInt.from_bytes(R_AT_Z)) % q

	o = (BigUInt.from_bytes(O_AT_Z) + gamma) % q

	s1 = (s1 * s2) % q
	s1 = (s1 * o) % q
	s1 = (s1 * alpha) % q
	s1 = (s1 * BigUInt.from_bytes(GRAND_PRODUCT_AT_Z_OMEGA)) % q

	s1 = (s1 + PI + q - alpha2Lagrange)  % q
	linearized_poly_at_z = (q - s1)

	# compute the folded commitment to H
	n2 = VK_DOMAIN_SIZE + BigUInt(2)
	zn2 = expmod(zeta, n2, q)
	folded_h = ec.scalar_mul(EC.BLS12_381g1, H_2, zn2.bytes)
	folded_h = ec.add(EC.BLS12_381g1, folded_h, H_1)
	folded_h = ec.scalar_mul(EC.BLS12_381g1, folded_h, zn2.bytes)
	folded_h = ec.add(EC.BLS12_381g1, folded_h, H_0)
	znminus1 = (expmod(zeta, VK_DOMAIN_SIZE, q) + q - BigUInt(1)) % q
	folded_h = ec.scalar_mul(EC.BLS12_381g1, folded_h, znminus1.bytes)
	folded_h = invert(folded_h)

	# compute commitment to linearization polynomial
	u = (BigUInt.from_bytes(GRAND_PRODUCT_AT_Z_OMEGA) * beta) % q
	v = (BigUInt.from_bytes(S1_AT_Z) * beta) % q
	v = (v + BigUInt.from_bytes(L_AT_Z) + gamma) % q
	w  = (BigUInt.from_bytes(S2_AT_Z) * beta) % q
	w = (w + BigUInt.from_bytes(R_AT_Z) + gamma) % q

	s1 = (u * v) % q
	s1 = (s1 * w) % q
	s1 = (s1 * alpha) % q

	coset_square = (VK_COSET_SHIFT * VK_COSET_SHIFT) % q
	betazeta = (beta * zeta) % q
	u = (betazeta + BigUInt.from_bytes(L_AT_Z) + gamma) % q

	v = (betazeta * VK_COSET_SHIFT) % q
	v = (v + BigUInt.from_bytes(R_AT_Z) + gamma) % q

	w = (betazeta * coset_square) % q
	w = (w + BigUInt.from_bytes(O_AT_Z) + gamma) % q

	s2 = (u * v) % q
	s2 = q - ((s2 * w) % q)
	s2 = (s2 * alpha + alpha2Lagrange) % q

	lin_poly_com = ec.scalar_mul(EC.BLS12_381g1, VK_QL, L_AT_Z)

	add_term = ec.scalar_mul(EC.BLS12_381g1, VK_QR, R_AT_Z)
	lin_poly_com = ec.add(EC.BLS12_381g1, lin_poly_com, add_term)

	add_term = ec.scalar_mul(EC.BLS12_381g1, VK_QO, O_AT_Z)
	lin_poly_com = ec.add(EC.BLS12_381g1, lin_poly_com, add_term)

	ab = (BigUInt.from_bytes(L_AT_Z) * BigUInt.from_bytes(R_AT_Z)) % q
	add_term = ec.scalar_mul(EC.BLS12_381g1, VK_QM, ab.bytes)
	lin_poly_com = ec.add(EC.BLS12_381g1, lin_poly_com, add_term)
	lin_poly_com = ec.add(EC.BLS12_381g1, lin_poly_com, VK_QK)

	add_term = ec.scalar_mul(EC.BLS12_381g1, VK_S3, s1.bytes)
	lin_poly_com = ec.add(EC.BLS12_381g1, lin_poly_com, add_term)

	add_term = ec.scalar_mul(EC.BLS12_381g1, GRAND_PRODUCT, s2.bytes)
	lin_poly_com = ec.add(EC.BLS12_381g1, lin_poly_com, add_term)

	lin_poly_com = ec.add(EC.BLS12_381g1, lin_poly_com, folded_h)

	# generate challenge to fold the opening proofs
	linearized_poly_at_z_bytes = bzero(32) | linearized_poly_at_z.bytes
	r_pre = sha256(b'gamma' + UInt256(zeta).bytes + lin_poly_com
		 + fs(L_COM) + fs(R_COM) + fs(O_COM) + VK_S1_fs + VK_S2_fs
		 + linearized_poly_at_z_bytes + L_AT_Z + R_AT_Z
		 + O_AT_Z + S1_AT_Z + S2_AT_Z
		 + GRAND_PRODUCT_AT_Z_OMEGA)
	r = curvemod(r_pre)
	r_acc = r

	# fold the proof in one point
	digest = lin_poly_com
	claims =  linearized_poly_at_z

	add_term = ec.scalar_mul(EC.BLS12_381g1, L_COM, r_acc.bytes)
	digest = ec.add(EC.BLS12_381g1, digest, add_term)
	claims = (claims + (BigUInt.from_bytes(L_AT_Z) * r_acc)) % q

	r_acc = (r_acc * r) % q
	add_term = ec.scalar_mul(EC.BLS12_381g1, R_COM, r_acc.bytes)
	digest = ec.add(EC.BLS12_381g1, digest, add_term)
	claims = (claims + (BigUInt.from_bytes(R_AT_Z) * r_acc)) % q

	r_acc = (r_acc * r) % q
	add_term = ec.scalar_mul(EC.BLS12_381g1, O_COM, r_acc.bytes)
	digest = ec.add(EC.BLS12_381g1, digest, add_term)
	claims = (claims + (BigUInt.from_bytes(O_AT_Z) * r_acc)) % q

	r_acc = (r_acc * r) % q
	add_term = ec.scalar_mul(EC.BLS12_381g1, VK_S1, r_acc.bytes)
	digest = ec.add(EC.BLS12_381g1, digest, add_term)
	claims = (claims + (BigUInt.from_bytes(S1_AT_Z) * r_acc)) % q

	r_acc = (r_acc * r) % q
	add_term = ec.scalar_mul(EC.BLS12_381g1, VK_S2, r_acc.bytes)
	digest = ec.add(EC.BLS12_381g1, digest, add_term)
	claims = (claims + (BigUInt.from_bytes(S2_AT_Z) * r_acc)) % q

	# verify the folded proof
	r_pre = sha256(digest + BATCH_OPENING_AT_Z + fs(GRAND_PRODUCT)
			+ OPENING_AT_Z_OMEGA + UInt256(zeta).bytes + UInt256(r).bytes)
	r = curvemod(r_pre)

	quotient = BATCH_OPENING_AT_Z
	add_term = ec.scalar_mul(EC.BLS12_381g1, OPENING_AT_Z_OMEGA, r.bytes)
	quotient = ec.add(EC.BLS12_381g1, quotient, add_term)

	add_term = ec.scalar_mul(EC.BLS12_381g1, GRAND_PRODUCT, r.bytes)
	digest = ec.add(EC.BLS12_381g1, digest, add_term)

	claims = (claims + (BigUInt.from_bytes(GRAND_PRODUCT_AT_Z_OMEGA)
			  * r)) % q
	G1_SRS = (bzero(48) | BigUInt(G1_SRS_X).bytes) + (bzero(48) | BigUInt(G1_SRS_Y).bytes)
	claims_com = ec.scalar_mul(EC.BLS12_381g1, G1_SRS, claims.bytes)

	digest = ec.add(EC.BLS12_381g1, digest, invert(claims_com))

	points_quotient = ec.scalar_mul(EC.BLS12_381g1, BATCH_OPENING_AT_Z, zeta.bytes)

	zeta_omega = (zeta * VK_OMEGA) % q
	r = (r * zeta_omega) % q
	add_term = ec.scalar_mul(EC.BLS12_381g1, OPENING_AT_Z_OMEGA, r.bytes)
	points_quotient = ec.add(EC.BLS12_381g1, points_quotient, add_term)

	digest = ec.add(EC.BLS12_381g1, digest, points_quotient)
	quotient = invert(quotient)

	g2 = ((bzero(48) | BigUInt(G2_SRS_0_X_1).bytes) + (bzero(48) | BigUInt(G2_SRS_0_X_0).bytes)
	+ (bzero(48) | BigUInt(G2_SRS_0_Y_1).bytes) + (bzero(48) | BigUInt(G2_SRS_0_Y_0).bytes)
	+ (bzero(48) | BigUInt(G2_SRS_1_X_1).bytes) + (bzero(48) | BigUInt(G2_SRS_1_X_0).bytes)
	+ (bzero(48) | BigUInt(G2_SRS_1_Y_1).bytes) + (bzero(48) | BigUInt(G2_SRS_1_Y_0).bytes))

	check = ec.pairing_check(EC.BLS12_381g1, digest + quotient, g2)
	return check


@subroutine
def expmod(base: BigUInt, exponent: BigUInt, modulus: BigUInt) -> BigUInt:
	"""Compute base^exponent % modulus."""
	result = BigUInt(1)
	while exponent > 0:
		if exponent % 2 == 1:
			result = (result * base) % modulus
		exponent = exponent // 2
		base = (base * base) % modulus
	return result

@subroutine
def curvemod(x: Bytes) -> BigUInt:
	"""Compute x % R_MOD."""
	return BigUInt.from_bytes(x) % BigUInt(R_MOD)

@subroutine
def invert(p : Bytes) -> Bytes:
	"""Invert a point on the curve."""
	x = BigUInt.from_bytes(p[:48])
	y = BigUInt.from_bytes(p[48:])
	if y == BigUInt(0):
		return p
	neg_y = BigUInt(P_MOD) - y
	return x.bytes + (bzero(48) | (neg_y).bytes)

@subroutine
def fs(p: Bytes) -> Bytes:
	"""If p is the point at infinity, mask the first bit with 1
	to match gnark's encoding for the fiat-shamir challenge."""
	if p == bzero(96):
		return setbit_bytes(p, 0, True)
	return p
