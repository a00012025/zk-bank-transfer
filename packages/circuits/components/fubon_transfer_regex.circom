pragma circom 2.1.5;

include "@zk-email/zk-regex-circom/circuits/regex_helpers.circom";

// regex: =a3=20[0-9]?[0-9]?,?[0-9]?[0-9]?[0-9]=[0-9a-z=<>"\r\n/]+=09012(=\r\n)?\((=\r\n)?(=[0-9a-f][0-9a-f])+\)-[0-9]{6}\*\*\*\*[0-9]{4}
template FubonTransferRegex(msg_bytes) {
	signal input msg[msg_bytes];
	signal output out;

	var num_bytes = msg_bytes+1;
	signal in[num_bytes];
	in[0]<==255;
	for (var i = 0; i < msg_bytes; i++) {
		in[i+1] <== msg[i];
	}

	component eq[28][num_bytes];
	component lt[2][num_bytes];
	component and[76][num_bytes];
	component multi_or[39][num_bytes];
	signal states[num_bytes+1][47];
	component state_changed[num_bytes];

	states[0][0] <== 1;
	for (var i = 1; i < 47; i++) {
		states[0][i] <== 0;
	}

	for (var i = 0; i < num_bytes; i++) {
		state_changed[i] = MultiOR(46);
		eq[0][i] = IsEqual();
		eq[0][i].in[0] <== in[i];
		eq[0][i].in[1] <== 61;
		and[0][i] = AND();
		and[0][i].a <== states[i][0];
		and[0][i].b <== eq[0][i].out;
		states[i+1][1] <== and[0][i].out;
		state_changed[i].in[0] <== states[i+1][1];
		eq[1][i] = IsEqual();
		eq[1][i].in[0] <== in[i];
		eq[1][i].in[1] <== 97;
		and[1][i] = AND();
		and[1][i].a <== states[i][1];
		and[1][i].b <== eq[1][i].out;
		states[i+1][2] <== and[1][i].out;
		state_changed[i].in[1] <== states[i+1][2];
		eq[2][i] = IsEqual();
		eq[2][i].in[0] <== in[i];
		eq[2][i].in[1] <== 51;
		and[2][i] = AND();
		and[2][i].a <== states[i][2];
		and[2][i].b <== eq[2][i].out;
		states[i+1][3] <== and[2][i].out;
		state_changed[i].in[2] <== states[i+1][3];
		and[3][i] = AND();
		and[3][i].a <== states[i][3];
		and[3][i].b <== eq[0][i].out;
		states[i+1][4] <== and[3][i].out;
		state_changed[i].in[3] <== states[i+1][4];
		eq[3][i] = IsEqual();
		eq[3][i].in[0] <== in[i];
		eq[3][i].in[1] <== 50;
		and[4][i] = AND();
		and[4][i].a <== states[i][4];
		and[4][i].b <== eq[3][i].out;
		states[i+1][5] <== and[4][i].out;
		state_changed[i].in[4] <== states[i+1][5];
		eq[4][i] = IsEqual();
		eq[4][i].in[0] <== in[i];
		eq[4][i].in[1] <== 48;
		and[5][i] = AND();
		and[5][i].a <== states[i][5];
		and[5][i].b <== eq[4][i].out;
		states[i+1][6] <== and[5][i].out;
		state_changed[i].in[5] <== states[i+1][6];
		eq[5][i] = IsEqual();
		eq[5][i].in[0] <== in[i];
		eq[5][i].in[1] <== 44;
		and[6][i] = AND();
		and[6][i].a <== states[i][9];
		and[6][i].b <== eq[5][i].out;
		and[7][i] = AND();
		and[7][i].a <== states[i][6];
		and[7][i].b <== eq[5][i].out;
		and[8][i] = AND();
		and[8][i].a <== states[i][8];
		and[8][i].b <== eq[5][i].out;
		multi_or[0][i] = MultiOR(3);
		multi_or[0][i].in[0] <== and[6][i].out;
		multi_or[0][i].in[1] <== and[7][i].out;
		multi_or[0][i].in[2] <== and[8][i].out;
		states[i+1][7] <== multi_or[0][i].out;
		state_changed[i].in[6] <== states[i+1][7];
		eq[6][i] = IsEqual();
		eq[6][i].in[0] <== in[i];
		eq[6][i].in[1] <== 52;
		eq[7][i] = IsEqual();
		eq[7][i].in[0] <== in[i];
		eq[7][i].in[1] <== 55;
		eq[8][i] = IsEqual();
		eq[8][i].in[0] <== in[i];
		eq[8][i].in[1] <== 54;
		eq[9][i] = IsEqual();
		eq[9][i].in[0] <== in[i];
		eq[9][i].in[1] <== 49;
		eq[10][i] = IsEqual();
		eq[10][i].in[0] <== in[i];
		eq[10][i].in[1] <== 57;
		eq[11][i] = IsEqual();
		eq[11][i].in[0] <== in[i];
		eq[11][i].in[1] <== 56;
		eq[12][i] = IsEqual();
		eq[12][i].in[0] <== in[i];
		eq[12][i].in[1] <== 53;
		and[9][i] = AND();
		and[9][i].a <== states[i][6];
		multi_or[1][i] = MultiOR(10);
		multi_or[1][i].in[0] <== eq[6][i].out;
		multi_or[1][i].in[1] <== eq[7][i].out;
		multi_or[1][i].in[2] <== eq[2][i].out;
		multi_or[1][i].in[3] <== eq[8][i].out;
		multi_or[1][i].in[4] <== eq[9][i].out;
		multi_or[1][i].in[5] <== eq[3][i].out;
		multi_or[1][i].in[6] <== eq[10][i].out;
		multi_or[1][i].in[7] <== eq[11][i].out;
		multi_or[1][i].in[8] <== eq[12][i].out;
		multi_or[1][i].in[9] <== eq[4][i].out;
		and[9][i].b <== multi_or[1][i].out;
		states[i+1][8] <== and[9][i].out;
		state_changed[i].in[7] <== states[i+1][8];
		and[10][i] = AND();
		and[10][i].a <== states[i][8];
		multi_or[2][i] = MultiOR(10);
		multi_or[2][i].in[0] <== eq[10][i].out;
		multi_or[2][i].in[1] <== eq[12][i].out;
		multi_or[2][i].in[2] <== eq[2][i].out;
		multi_or[2][i].in[3] <== eq[3][i].out;
		multi_or[2][i].in[4] <== eq[6][i].out;
		multi_or[2][i].in[5] <== eq[7][i].out;
		multi_or[2][i].in[6] <== eq[11][i].out;
		multi_or[2][i].in[7] <== eq[9][i].out;
		multi_or[2][i].in[8] <== eq[4][i].out;
		multi_or[2][i].in[9] <== eq[8][i].out;
		and[10][i].b <== multi_or[2][i].out;
		states[i+1][9] <== and[10][i].out;
		state_changed[i].in[8] <== states[i+1][9];
		and[11][i] = AND();
		and[11][i].a <== states[i][13];
		and[11][i].b <== eq[0][i].out;
		and[12][i] = AND();
		and[12][i].a <== states[i][11];
		and[12][i].b <== eq[0][i].out;
		and[13][i] = AND();
		and[13][i].a <== states[i][8];
		and[13][i].b <== eq[0][i].out;
		and[14][i] = AND();
		and[14][i].a <== states[i][15];
		and[14][i].b <== eq[0][i].out;
		and[15][i] = AND();
		and[15][i].a <== states[i][9];
		and[15][i].b <== eq[0][i].out;
		multi_or[3][i] = MultiOR(5);
		multi_or[3][i].in[0] <== and[11][i].out;
		multi_or[3][i].in[1] <== and[12][i].out;
		multi_or[3][i].in[2] <== and[13][i].out;
		multi_or[3][i].in[3] <== and[14][i].out;
		multi_or[3][i].in[4] <== and[15][i].out;
		states[i+1][10] <== multi_or[3][i].out;
		state_changed[i].in[9] <== states[i+1][10];
		and[16][i] = AND();
		and[16][i].a <== states[i][9];
		multi_or[4][i] = MultiOR(10);
		multi_or[4][i].in[0] <== eq[7][i].out;
		multi_or[4][i].in[1] <== eq[3][i].out;
		multi_or[4][i].in[2] <== eq[11][i].out;
		multi_or[4][i].in[3] <== eq[4][i].out;
		multi_or[4][i].in[4] <== eq[10][i].out;
		multi_or[4][i].in[5] <== eq[2][i].out;
		multi_or[4][i].in[6] <== eq[6][i].out;
		multi_or[4][i].in[7] <== eq[9][i].out;
		multi_or[4][i].in[8] <== eq[8][i].out;
		multi_or[4][i].in[9] <== eq[12][i].out;
		and[16][i].b <== multi_or[4][i].out;
		and[17][i] = AND();
		and[17][i].a <== states[i][7];
		multi_or[5][i] = MultiOR(10);
		multi_or[5][i].in[0] <== eq[4][i].out;
		multi_or[5][i].in[1] <== eq[8][i].out;
		multi_or[5][i].in[2] <== eq[7][i].out;
		multi_or[5][i].in[3] <== eq[2][i].out;
		multi_or[5][i].in[4] <== eq[11][i].out;
		multi_or[5][i].in[5] <== eq[10][i].out;
		multi_or[5][i].in[6] <== eq[9][i].out;
		multi_or[5][i].in[7] <== eq[3][i].out;
		multi_or[5][i].in[8] <== eq[6][i].out;
		multi_or[5][i].in[9] <== eq[12][i].out;
		and[17][i].b <== multi_or[5][i].out;
		multi_or[6][i] = MultiOR(2);
		multi_or[6][i].in[0] <== and[16][i].out;
		multi_or[6][i].in[1] <== and[17][i].out;
		states[i+1][11] <== multi_or[6][i].out;
		state_changed[i].in[10] <== states[i+1][11];
		lt[0][i] = LessEqThan(8);
		lt[0][i].in[0] <== 97;
		lt[0][i].in[1] <== in[i];
		lt[1][i] = LessEqThan(8);
		lt[1][i].in[0] <== in[i];
		lt[1][i].in[1] <== 122;
		and[18][i] = AND();
		and[18][i].a <== lt[0][i].out;
		and[18][i].b <== lt[1][i].out;
		eq[13][i] = IsEqual();
		eq[13][i].in[0] <== in[i];
		eq[13][i].in[1] <== 62;
		eq[14][i] = IsEqual();
		eq[14][i].in[0] <== in[i];
		eq[14][i].in[1] <== 47;
		eq[15][i] = IsEqual();
		eq[15][i].in[0] <== in[i];
		eq[15][i].in[1] <== 10;
		eq[16][i] = IsEqual();
		eq[16][i].in[0] <== in[i];
		eq[16][i].in[1] <== 92;
		eq[17][i] = IsEqual();
		eq[17][i].in[0] <== in[i];
		eq[17][i].in[1] <== 13;
		eq[18][i] = IsEqual();
		eq[18][i].in[0] <== in[i];
		eq[18][i].in[1] <== 60;
		and[19][i] = AND();
		and[19][i].a <== states[i][14];
		multi_or[7][i] = MultiOR(16);
		multi_or[7][i].in[0] <== and[18][i].out;
		multi_or[7][i].in[1] <== eq[13][i].out;
		multi_or[7][i].in[2] <== eq[14][i].out;
		multi_or[7][i].in[3] <== eq[15][i].out;
		multi_or[7][i].in[4] <== eq[6][i].out;
		multi_or[7][i].in[5] <== eq[16][i].out;
		multi_or[7][i].in[6] <== eq[9][i].out;
		multi_or[7][i].in[7] <== eq[17][i].out;
		multi_or[7][i].in[8] <== eq[7][i].out;
		multi_or[7][i].in[9] <== eq[3][i].out;
		multi_or[7][i].in[10] <== eq[11][i].out;
		multi_or[7][i].in[11] <== eq[10][i].out;
		multi_or[7][i].in[12] <== eq[2][i].out;
		multi_or[7][i].in[13] <== eq[12][i].out;
		multi_or[7][i].in[14] <== eq[18][i].out;
		multi_or[7][i].in[15] <== eq[8][i].out;
		and[19][i].b <== multi_or[7][i].out;
		and[20][i] = AND();
		and[20][i].a <== states[i][16];
		multi_or[8][i] = MultiOR(16);
		multi_or[8][i].in[0] <== and[18][i].out;
		multi_or[8][i].in[1] <== eq[8][i].out;
		multi_or[8][i].in[2] <== eq[13][i].out;
		multi_or[8][i].in[3] <== eq[4][i].out;
		multi_or[8][i].in[4] <== eq[12][i].out;
		multi_or[8][i].in[5] <== eq[18][i].out;
		multi_or[8][i].in[6] <== eq[17][i].out;
		multi_or[8][i].in[7] <== eq[7][i].out;
		multi_or[8][i].in[8] <== eq[2][i].out;
		multi_or[8][i].in[9] <== eq[11][i].out;
		multi_or[8][i].in[10] <== eq[9][i].out;
		multi_or[8][i].in[11] <== eq[6][i].out;
		multi_or[8][i].in[12] <== eq[15][i].out;
		multi_or[8][i].in[13] <== eq[3][i].out;
		multi_or[8][i].in[14] <== eq[16][i].out;
		multi_or[8][i].in[15] <== eq[14][i].out;
		and[20][i].b <== multi_or[8][i].out;
		and[21][i] = AND();
		and[21][i].a <== states[i][18];
		multi_or[9][i] = MultiOR(16);
		multi_or[9][i].in[0] <== and[18][i].out;
		multi_or[9][i].in[1] <== eq[14][i].out;
		multi_or[9][i].in[2] <== eq[15][i].out;
		multi_or[9][i].in[3] <== eq[17][i].out;
		multi_or[9][i].in[4] <== eq[10][i].out;
		multi_or[9][i].in[5] <== eq[16][i].out;
		multi_or[9][i].in[6] <== eq[13][i].out;
		multi_or[9][i].in[7] <== eq[4][i].out;
		multi_or[9][i].in[8] <== eq[11][i].out;
		multi_or[9][i].in[9] <== eq[6][i].out;
		multi_or[9][i].in[10] <== eq[8][i].out;
		multi_or[9][i].in[11] <== eq[12][i].out;
		multi_or[9][i].in[12] <== eq[18][i].out;
		multi_or[9][i].in[13] <== eq[2][i].out;
		multi_or[9][i].in[14] <== eq[3][i].out;
		multi_or[9][i].in[15] <== eq[7][i].out;
		and[21][i].b <== multi_or[9][i].out;
		and[22][i] = AND();
		and[22][i].a <== states[i][19];
		multi_or[10][i] = MultiOR(16);
		multi_or[10][i].in[0] <== and[18][i].out;
		multi_or[10][i].in[1] <== eq[18][i].out;
		multi_or[10][i].in[2] <== eq[10][i].out;
		multi_or[10][i].in[3] <== eq[2][i].out;
		multi_or[10][i].in[4] <== eq[16][i].out;
		multi_or[10][i].in[5] <== eq[7][i].out;
		multi_or[10][i].in[6] <== eq[14][i].out;
		multi_or[10][i].in[7] <== eq[6][i].out;
		multi_or[10][i].in[8] <== eq[15][i].out;
		multi_or[10][i].in[9] <== eq[11][i].out;
		multi_or[10][i].in[10] <== eq[12][i].out;
		multi_or[10][i].in[11] <== eq[4][i].out;
		multi_or[10][i].in[12] <== eq[13][i].out;
		multi_or[10][i].in[13] <== eq[17][i].out;
		multi_or[10][i].in[14] <== eq[9][i].out;
		multi_or[10][i].in[15] <== eq[8][i].out;
		and[22][i].b <== multi_or[10][i].out;
		and[23][i] = AND();
		and[23][i].a <== states[i][22];
		multi_or[11][i] = MultiOR(15);
		multi_or[11][i].in[0] <== and[18][i].out;
		multi_or[11][i].in[1] <== eq[14][i].out;
		multi_or[11][i].in[2] <== eq[2][i].out;
		multi_or[11][i].in[3] <== eq[12][i].out;
		multi_or[11][i].in[4] <== eq[11][i].out;
		multi_or[11][i].in[5] <== eq[3][i].out;
		multi_or[11][i].in[6] <== eq[10][i].out;
		multi_or[11][i].in[7] <== eq[9][i].out;
		multi_or[11][i].in[8] <== eq[15][i].out;
		multi_or[11][i].in[9] <== eq[7][i].out;
		multi_or[11][i].in[10] <== eq[8][i].out;
		multi_or[11][i].in[11] <== eq[18][i].out;
		multi_or[11][i].in[12] <== eq[13][i].out;
		multi_or[11][i].in[13] <== eq[16][i].out;
		multi_or[11][i].in[14] <== eq[6][i].out;
		and[23][i].b <== multi_or[11][i].out;
		and[24][i] = AND();
		and[24][i].a <== states[i][23];
		multi_or[12][i] = MultiOR(16);
		multi_or[12][i].in[0] <== and[18][i].out;
		multi_or[12][i].in[1] <== eq[12][i].out;
		multi_or[12][i].in[2] <== eq[17][i].out;
		multi_or[12][i].in[3] <== eq[9][i].out;
		multi_or[12][i].in[4] <== eq[7][i].out;
		multi_or[12][i].in[5] <== eq[16][i].out;
		multi_or[12][i].in[6] <== eq[13][i].out;
		multi_or[12][i].in[7] <== eq[11][i].out;
		multi_or[12][i].in[8] <== eq[3][i].out;
		multi_or[12][i].in[9] <== eq[10][i].out;
		multi_or[12][i].in[10] <== eq[6][i].out;
		multi_or[12][i].in[11] <== eq[2][i].out;
		multi_or[12][i].in[12] <== eq[4][i].out;
		multi_or[12][i].in[13] <== eq[18][i].out;
		multi_or[12][i].in[14] <== eq[8][i].out;
		multi_or[12][i].in[15] <== eq[14][i].out;
		and[24][i].b <== multi_or[12][i].out;
		and[25][i] = AND();
		and[25][i].a <== states[i][20];
		multi_or[13][i] = MultiOR(17);
		multi_or[13][i].in[0] <== and[18][i].out;
		multi_or[13][i].in[1] <== eq[11][i].out;
		multi_or[13][i].in[2] <== eq[10][i].out;
		multi_or[13][i].in[3] <== eq[9][i].out;
		multi_or[13][i].in[4] <== eq[12][i].out;
		multi_or[13][i].in[5] <== eq[2][i].out;
		multi_or[13][i].in[6] <== eq[16][i].out;
		multi_or[13][i].in[7] <== eq[15][i].out;
		multi_or[13][i].in[8] <== eq[3][i].out;
		multi_or[13][i].in[9] <== eq[13][i].out;
		multi_or[13][i].in[10] <== eq[6][i].out;
		multi_or[13][i].in[11] <== eq[7][i].out;
		multi_or[13][i].in[12] <== eq[17][i].out;
		multi_or[13][i].in[13] <== eq[4][i].out;
		multi_or[13][i].in[14] <== eq[18][i].out;
		multi_or[13][i].in[15] <== eq[14][i].out;
		multi_or[13][i].in[16] <== eq[8][i].out;
		and[25][i].b <== multi_or[13][i].out;
		and[26][i] = AND();
		and[26][i].a <== states[i][25];
		multi_or[14][i] = MultiOR(17);
		multi_or[14][i].in[0] <== and[18][i].out;
		multi_or[14][i].in[1] <== eq[7][i].out;
		multi_or[14][i].in[2] <== eq[3][i].out;
		multi_or[14][i].in[3] <== eq[13][i].out;
		multi_or[14][i].in[4] <== eq[16][i].out;
		multi_or[14][i].in[5] <== eq[2][i].out;
		multi_or[14][i].in[6] <== eq[11][i].out;
		multi_or[14][i].in[7] <== eq[18][i].out;
		multi_or[14][i].in[8] <== eq[12][i].out;
		multi_or[14][i].in[9] <== eq[14][i].out;
		multi_or[14][i].in[10] <== eq[6][i].out;
		multi_or[14][i].in[11] <== eq[4][i].out;
		multi_or[14][i].in[12] <== eq[9][i].out;
		multi_or[14][i].in[13] <== eq[10][i].out;
		multi_or[14][i].in[14] <== eq[15][i].out;
		multi_or[14][i].in[15] <== eq[8][i].out;
		multi_or[14][i].in[16] <== eq[17][i].out;
		and[26][i].b <== multi_or[14][i].out;
		and[27][i] = AND();
		and[27][i].a <== states[i][12];
		multi_or[15][i] = MultiOR(17);
		multi_or[15][i].in[0] <== and[18][i].out;
		multi_or[15][i].in[1] <== eq[10][i].out;
		multi_or[15][i].in[2] <== eq[17][i].out;
		multi_or[15][i].in[3] <== eq[3][i].out;
		multi_or[15][i].in[4] <== eq[7][i].out;
		multi_or[15][i].in[5] <== eq[13][i].out;
		multi_or[15][i].in[6] <== eq[11][i].out;
		multi_or[15][i].in[7] <== eq[14][i].out;
		multi_or[15][i].in[8] <== eq[2][i].out;
		multi_or[15][i].in[9] <== eq[12][i].out;
		multi_or[15][i].in[10] <== eq[18][i].out;
		multi_or[15][i].in[11] <== eq[9][i].out;
		multi_or[15][i].in[12] <== eq[16][i].out;
		multi_or[15][i].in[13] <== eq[6][i].out;
		multi_or[15][i].in[14] <== eq[8][i].out;
		multi_or[15][i].in[15] <== eq[4][i].out;
		multi_or[15][i].in[16] <== eq[15][i].out;
		and[27][i].b <== multi_or[15][i].out;
		and[28][i] = AND();
		and[28][i].a <== states[i][10];
		multi_or[16][i] = MultiOR(18);
		multi_or[16][i].in[0] <== and[18][i].out;
		multi_or[16][i].in[1] <== eq[16][i].out;
		multi_or[16][i].in[2] <== eq[4][i].out;
		multi_or[16][i].in[3] <== eq[6][i].out;
		multi_or[16][i].in[4] <== eq[11][i].out;
		multi_or[16][i].in[5] <== eq[8][i].out;
		multi_or[16][i].in[6] <== eq[17][i].out;
		multi_or[16][i].in[7] <== eq[2][i].out;
		multi_or[16][i].in[8] <== eq[12][i].out;
		multi_or[16][i].in[9] <== eq[13][i].out;
		multi_or[16][i].in[10] <== eq[7][i].out;
		multi_or[16][i].in[11] <== eq[10][i].out;
		multi_or[16][i].in[12] <== eq[18][i].out;
		multi_or[16][i].in[13] <== eq[0][i].out;
		multi_or[16][i].in[14] <== eq[15][i].out;
		multi_or[16][i].in[15] <== eq[14][i].out;
		multi_or[16][i].in[16] <== eq[3][i].out;
		multi_or[16][i].in[17] <== eq[9][i].out;
		and[28][i].b <== multi_or[16][i].out;
		and[29][i] = AND();
		and[29][i].a <== states[i][17];
		multi_or[17][i] = MultiOR(16);
		multi_or[17][i].in[0] <== and[18][i].out;
		multi_or[17][i].in[1] <== eq[12][i].out;
		multi_or[17][i].in[2] <== eq[2][i].out;
		multi_or[17][i].in[3] <== eq[13][i].out;
		multi_or[17][i].in[4] <== eq[9][i].out;
		multi_or[17][i].in[5] <== eq[7][i].out;
		multi_or[17][i].in[6] <== eq[16][i].out;
		multi_or[17][i].in[7] <== eq[6][i].out;
		multi_or[17][i].in[8] <== eq[18][i].out;
		multi_or[17][i].in[9] <== eq[8][i].out;
		multi_or[17][i].in[10] <== eq[3][i].out;
		multi_or[17][i].in[11] <== eq[17][i].out;
		multi_or[17][i].in[12] <== eq[15][i].out;
		multi_or[17][i].in[13] <== eq[11][i].out;
		multi_or[17][i].in[14] <== eq[14][i].out;
		multi_or[17][i].in[15] <== eq[10][i].out;
		and[29][i].b <== multi_or[17][i].out;
		multi_or[18][i] = MultiOR(11);
		multi_or[18][i].in[0] <== and[19][i].out;
		multi_or[18][i].in[1] <== and[20][i].out;
		multi_or[18][i].in[2] <== and[21][i].out;
		multi_or[18][i].in[3] <== and[22][i].out;
		multi_or[18][i].in[4] <== and[23][i].out;
		multi_or[18][i].in[5] <== and[24][i].out;
		multi_or[18][i].in[6] <== and[25][i].out;
		multi_or[18][i].in[7] <== and[26][i].out;
		multi_or[18][i].in[8] <== and[27][i].out;
		multi_or[18][i].in[9] <== and[28][i].out;
		multi_or[18][i].in[10] <== and[29][i].out;
		states[i+1][12] <== multi_or[18][i].out;
		state_changed[i].in[11] <== states[i+1][12];
		and[30][i] = AND();
		and[30][i].a <== states[i][11];
		multi_or[19][i] = MultiOR(10);
		multi_or[19][i].in[0] <== eq[3][i].out;
		multi_or[19][i].in[1] <== eq[12][i].out;
		multi_or[19][i].in[2] <== eq[2][i].out;
		multi_or[19][i].in[3] <== eq[10][i].out;
		multi_or[19][i].in[4] <== eq[11][i].out;
		multi_or[19][i].in[5] <== eq[9][i].out;
		multi_or[19][i].in[6] <== eq[4][i].out;
		multi_or[19][i].in[7] <== eq[8][i].out;
		multi_or[19][i].in[8] <== eq[7][i].out;
		multi_or[19][i].in[9] <== eq[6][i].out;
		and[30][i].b <== multi_or[19][i].out;
		states[i+1][13] <== and[30][i].out;
		state_changed[i].in[12] <== states[i+1][13];
		and[31][i] = AND();
		and[31][i].a <== states[i][22];
		and[31][i].b <== eq[0][i].out;
		and[32][i] = AND();
		and[32][i].a <== states[i][16];
		and[32][i].b <== eq[0][i].out;
		and[33][i] = AND();
		and[33][i].a <== states[i][25];
		and[33][i].b <== eq[0][i].out;
		and[34][i] = AND();
		and[34][i].a <== states[i][18];
		and[34][i].b <== eq[0][i].out;
		and[35][i] = AND();
		and[35][i].a <== states[i][17];
		and[35][i].b <== eq[0][i].out;
		and[36][i] = AND();
		and[36][i].a <== states[i][14];
		and[36][i].b <== eq[0][i].out;
		and[37][i] = AND();
		and[37][i].a <== states[i][23];
		and[37][i].b <== eq[0][i].out;
		and[38][i] = AND();
		and[38][i].a <== states[i][19];
		and[38][i].b <== eq[0][i].out;
		and[39][i] = AND();
		and[39][i].a <== states[i][12];
		and[39][i].b <== eq[0][i].out;
		multi_or[20][i] = MultiOR(9);
		multi_or[20][i].in[0] <== and[31][i].out;
		multi_or[20][i].in[1] <== and[32][i].out;
		multi_or[20][i].in[2] <== and[33][i].out;
		multi_or[20][i].in[3] <== and[34][i].out;
		multi_or[20][i].in[4] <== and[35][i].out;
		multi_or[20][i].in[5] <== and[36][i].out;
		multi_or[20][i].in[6] <== and[37][i].out;
		multi_or[20][i].in[7] <== and[38][i].out;
		multi_or[20][i].in[8] <== and[39][i].out;
		states[i+1][14] <== multi_or[20][i].out;
		state_changed[i].in[13] <== states[i+1][14];
		and[40][i] = AND();
		and[40][i].a <== states[i][13];
		multi_or[21][i] = MultiOR(10);
		multi_or[21][i].in[0] <== eq[8][i].out;
		multi_or[21][i].in[1] <== eq[6][i].out;
		multi_or[21][i].in[2] <== eq[10][i].out;
		multi_or[21][i].in[3] <== eq[4][i].out;
		multi_or[21][i].in[4] <== eq[9][i].out;
		multi_or[21][i].in[5] <== eq[2][i].out;
		multi_or[21][i].in[6] <== eq[11][i].out;
		multi_or[21][i].in[7] <== eq[7][i].out;
		multi_or[21][i].in[8] <== eq[3][i].out;
		multi_or[21][i].in[9] <== eq[12][i].out;
		and[40][i].b <== multi_or[21][i].out;
		states[i+1][15] <== and[40][i].out;
		state_changed[i].in[14] <== states[i+1][15];
		and[41][i] = AND();
		and[41][i].a <== states[i][14];
		and[41][i].b <== eq[4][i].out;
		and[42][i] = AND();
		and[42][i].a <== states[i][22];
		and[42][i].b <== eq[4][i].out;
		multi_or[22][i] = MultiOR(2);
		multi_or[22][i].in[0] <== and[41][i].out;
		multi_or[22][i].in[1] <== and[42][i].out;
		states[i+1][16] <== multi_or[22][i].out;
		state_changed[i].in[15] <== states[i+1][16];
		and[43][i] = AND();
		and[43][i].a <== states[i][16];
		and[43][i].b <== eq[10][i].out;
		states[i+1][17] <== and[43][i].out;
		state_changed[i].in[16] <== states[i+1][17];
		and[44][i] = AND();
		and[44][i].a <== states[i][17];
		and[44][i].b <== eq[4][i].out;
		states[i+1][18] <== and[44][i].out;
		state_changed[i].in[17] <== states[i+1][18];
		and[45][i] = AND();
		and[45][i].a <== states[i][18];
		and[45][i].b <== eq[9][i].out;
		states[i+1][19] <== and[45][i].out;
		state_changed[i].in[18] <== states[i+1][19];
		and[46][i] = AND();
		and[46][i].a <== states[i][19];
		and[46][i].b <== eq[3][i].out;
		states[i+1][20] <== and[46][i].out;
		state_changed[i].in[19] <== states[i+1][20];
		eq[19][i] = IsEqual();
		eq[19][i].in[0] <== in[i];
		eq[19][i].in[1] <== 40;
		and[47][i] = AND();
		and[47][i].a <== states[i][20];
		and[47][i].b <== eq[19][i].out;
		and[48][i] = AND();
		and[48][i].a <== states[i][25];
		and[48][i].b <== eq[19][i].out;
		multi_or[23][i] = MultiOR(2);
		multi_or[23][i].in[0] <== and[47][i].out;
		multi_or[23][i].in[1] <== and[48][i].out;
		states[i+1][21] <== multi_or[23][i].out;
		state_changed[i].in[20] <== states[i+1][21];
		and[49][i] = AND();
		and[49][i].a <== states[i][20];
		and[49][i].b <== eq[0][i].out;
		states[i+1][22] <== and[49][i].out;
		state_changed[i].in[21] <== states[i+1][22];
		and[50][i] = AND();
		and[50][i].a <== states[i][22];
		and[50][i].b <== eq[17][i].out;
		states[i+1][23] <== and[50][i].out;
		state_changed[i].in[22] <== states[i+1][23];
		and[51][i] = AND();
		and[51][i].a <== states[i][21];
		and[51][i].b <== eq[0][i].out;
		states[i+1][24] <== and[51][i].out;
		state_changed[i].in[23] <== states[i+1][24];
		and[52][i] = AND();
		and[52][i].a <== states[i][23];
		and[52][i].b <== eq[15][i].out;
		states[i+1][25] <== and[52][i].out;
		state_changed[i].in[24] <== states[i+1][25];
		and[53][i] = AND();
		and[53][i].a <== states[i][24];
		and[53][i].b <== eq[17][i].out;
		states[i+1][26] <== and[53][i].out;
		state_changed[i].in[25] <== states[i+1][26];
		eq[20][i] = IsEqual();
		eq[20][i].in[0] <== in[i];
		eq[20][i].in[1] <== 101;
		eq[21][i] = IsEqual();
		eq[21][i].in[0] <== in[i];
		eq[21][i].in[1] <== 100;
		eq[22][i] = IsEqual();
		eq[22][i].in[0] <== in[i];
		eq[22][i].in[1] <== 98;
		eq[23][i] = IsEqual();
		eq[23][i].in[0] <== in[i];
		eq[23][i].in[1] <== 102;
		eq[24][i] = IsEqual();
		eq[24][i].in[0] <== in[i];
		eq[24][i].in[1] <== 99;
		and[54][i] = AND();
		and[54][i].a <== states[i][24];
		multi_or[24][i] = MultiOR(16);
		multi_or[24][i].in[0] <== eq[4][i].out;
		multi_or[24][i].in[1] <== eq[1][i].out;
		multi_or[24][i].in[2] <== eq[12][i].out;
		multi_or[24][i].in[3] <== eq[20][i].out;
		multi_or[24][i].in[4] <== eq[11][i].out;
		multi_or[24][i].in[5] <== eq[7][i].out;
		multi_or[24][i].in[6] <== eq[21][i].out;
		multi_or[24][i].in[7] <== eq[22][i].out;
		multi_or[24][i].in[8] <== eq[9][i].out;
		multi_or[24][i].in[9] <== eq[8][i].out;
		multi_or[24][i].in[10] <== eq[10][i].out;
		multi_or[24][i].in[11] <== eq[6][i].out;
		multi_or[24][i].in[12] <== eq[23][i].out;
		multi_or[24][i].in[13] <== eq[2][i].out;
		multi_or[24][i].in[14] <== eq[24][i].out;
		multi_or[24][i].in[15] <== eq[3][i].out;
		and[54][i].b <== multi_or[24][i].out;
		and[55][i] = AND();
		and[55][i].a <== states[i][31];
		multi_or[25][i] = MultiOR(16);
		multi_or[25][i].in[0] <== eq[12][i].out;
		multi_or[25][i].in[1] <== eq[11][i].out;
		multi_or[25][i].in[2] <== eq[4][i].out;
		multi_or[25][i].in[3] <== eq[6][i].out;
		multi_or[25][i].in[4] <== eq[20][i].out;
		multi_or[25][i].in[5] <== eq[9][i].out;
		multi_or[25][i].in[6] <== eq[21][i].out;
		multi_or[25][i].in[7] <== eq[3][i].out;
		multi_or[25][i].in[8] <== eq[2][i].out;
		multi_or[25][i].in[9] <== eq[24][i].out;
		multi_or[25][i].in[10] <== eq[22][i].out;
		multi_or[25][i].in[11] <== eq[7][i].out;
		multi_or[25][i].in[12] <== eq[10][i].out;
		multi_or[25][i].in[13] <== eq[23][i].out;
		multi_or[25][i].in[14] <== eq[1][i].out;
		multi_or[25][i].in[15] <== eq[8][i].out;
		and[55][i].b <== multi_or[25][i].out;
		multi_or[26][i] = MultiOR(2);
		multi_or[26][i].in[0] <== and[54][i].out;
		multi_or[26][i].in[1] <== and[55][i].out;
		states[i+1][27] <== multi_or[26][i].out;
		state_changed[i].in[26] <== states[i+1][27];
		and[56][i] = AND();
		and[56][i].a <== states[i][27];
		multi_or[27][i] = MultiOR(16);
		multi_or[27][i].in[0] <== eq[11][i].out;
		multi_or[27][i].in[1] <== eq[22][i].out;
		multi_or[27][i].in[2] <== eq[23][i].out;
		multi_or[27][i].in[3] <== eq[21][i].out;
		multi_or[27][i].in[4] <== eq[6][i].out;
		multi_or[27][i].in[5] <== eq[24][i].out;
		multi_or[27][i].in[6] <== eq[10][i].out;
		multi_or[27][i].in[7] <== eq[1][i].out;
		multi_or[27][i].in[8] <== eq[7][i].out;
		multi_or[27][i].in[9] <== eq[2][i].out;
		multi_or[27][i].in[10] <== eq[20][i].out;
		multi_or[27][i].in[11] <== eq[4][i].out;
		multi_or[27][i].in[12] <== eq[9][i].out;
		multi_or[27][i].in[13] <== eq[3][i].out;
		multi_or[27][i].in[14] <== eq[8][i].out;
		multi_or[27][i].in[15] <== eq[12][i].out;
		and[56][i].b <== multi_or[27][i].out;
		states[i+1][28] <== and[56][i].out;
		state_changed[i].in[27] <== states[i+1][28];
		and[57][i] = AND();
		and[57][i].a <== states[i][26];
		and[57][i].b <== eq[15][i].out;
		states[i+1][29] <== and[57][i].out;
		state_changed[i].in[28] <== states[i+1][29];
		eq[25][i] = IsEqual();
		eq[25][i].in[0] <== in[i];
		eq[25][i].in[1] <== 41;
		and[58][i] = AND();
		and[58][i].a <== states[i][28];
		and[58][i].b <== eq[25][i].out;
		states[i+1][30] <== and[58][i].out;
		state_changed[i].in[29] <== states[i+1][30];
		and[59][i] = AND();
		and[59][i].a <== states[i][28];
		and[59][i].b <== eq[0][i].out;
		and[60][i] = AND();
		and[60][i].a <== states[i][29];
		and[60][i].b <== eq[0][i].out;
		multi_or[28][i] = MultiOR(2);
		multi_or[28][i].in[0] <== and[59][i].out;
		multi_or[28][i].in[1] <== and[60][i].out;
		states[i+1][31] <== multi_or[28][i].out;
		state_changed[i].in[30] <== states[i+1][31];
		eq[26][i] = IsEqual();
		eq[26][i].in[0] <== in[i];
		eq[26][i].in[1] <== 45;
		and[61][i] = AND();
		and[61][i].a <== states[i][30];
		and[61][i].b <== eq[26][i].out;
		states[i+1][32] <== and[61][i].out;
		state_changed[i].in[31] <== states[i+1][32];
		and[62][i] = AND();
		and[62][i].a <== states[i][32];
		multi_or[29][i] = MultiOR(10);
		multi_or[29][i].in[0] <== eq[3][i].out;
		multi_or[29][i].in[1] <== eq[2][i].out;
		multi_or[29][i].in[2] <== eq[8][i].out;
		multi_or[29][i].in[3] <== eq[6][i].out;
		multi_or[29][i].in[4] <== eq[12][i].out;
		multi_or[29][i].in[5] <== eq[7][i].out;
		multi_or[29][i].in[6] <== eq[9][i].out;
		multi_or[29][i].in[7] <== eq[4][i].out;
		multi_or[29][i].in[8] <== eq[10][i].out;
		multi_or[29][i].in[9] <== eq[11][i].out;
		and[62][i].b <== multi_or[29][i].out;
		states[i+1][33] <== and[62][i].out;
		state_changed[i].in[32] <== states[i+1][33];
		and[63][i] = AND();
		and[63][i].a <== states[i][33];
		multi_or[30][i] = MultiOR(10);
		multi_or[30][i].in[0] <== eq[12][i].out;
		multi_or[30][i].in[1] <== eq[3][i].out;
		multi_or[30][i].in[2] <== eq[6][i].out;
		multi_or[30][i].in[3] <== eq[11][i].out;
		multi_or[30][i].in[4] <== eq[10][i].out;
		multi_or[30][i].in[5] <== eq[9][i].out;
		multi_or[30][i].in[6] <== eq[2][i].out;
		multi_or[30][i].in[7] <== eq[8][i].out;
		multi_or[30][i].in[8] <== eq[4][i].out;
		multi_or[30][i].in[9] <== eq[7][i].out;
		and[63][i].b <== multi_or[30][i].out;
		states[i+1][34] <== and[63][i].out;
		state_changed[i].in[33] <== states[i+1][34];
		and[64][i] = AND();
		and[64][i].a <== states[i][34];
		multi_or[31][i] = MultiOR(10);
		multi_or[31][i].in[0] <== eq[11][i].out;
		multi_or[31][i].in[1] <== eq[4][i].out;
		multi_or[31][i].in[2] <== eq[7][i].out;
		multi_or[31][i].in[3] <== eq[10][i].out;
		multi_or[31][i].in[4] <== eq[6][i].out;
		multi_or[31][i].in[5] <== eq[9][i].out;
		multi_or[31][i].in[6] <== eq[2][i].out;
		multi_or[31][i].in[7] <== eq[12][i].out;
		multi_or[31][i].in[8] <== eq[8][i].out;
		multi_or[31][i].in[9] <== eq[3][i].out;
		and[64][i].b <== multi_or[31][i].out;
		states[i+1][35] <== and[64][i].out;
		state_changed[i].in[34] <== states[i+1][35];
		and[65][i] = AND();
		and[65][i].a <== states[i][35];
		multi_or[32][i] = MultiOR(10);
		multi_or[32][i].in[0] <== eq[10][i].out;
		multi_or[32][i].in[1] <== eq[12][i].out;
		multi_or[32][i].in[2] <== eq[3][i].out;
		multi_or[32][i].in[3] <== eq[8][i].out;
		multi_or[32][i].in[4] <== eq[7][i].out;
		multi_or[32][i].in[5] <== eq[11][i].out;
		multi_or[32][i].in[6] <== eq[2][i].out;
		multi_or[32][i].in[7] <== eq[6][i].out;
		multi_or[32][i].in[8] <== eq[9][i].out;
		multi_or[32][i].in[9] <== eq[4][i].out;
		and[65][i].b <== multi_or[32][i].out;
		states[i+1][36] <== and[65][i].out;
		state_changed[i].in[35] <== states[i+1][36];
		and[66][i] = AND();
		and[66][i].a <== states[i][36];
		multi_or[33][i] = MultiOR(10);
		multi_or[33][i].in[0] <== eq[10][i].out;
		multi_or[33][i].in[1] <== eq[12][i].out;
		multi_or[33][i].in[2] <== eq[6][i].out;
		multi_or[33][i].in[3] <== eq[9][i].out;
		multi_or[33][i].in[4] <== eq[8][i].out;
		multi_or[33][i].in[5] <== eq[7][i].out;
		multi_or[33][i].in[6] <== eq[2][i].out;
		multi_or[33][i].in[7] <== eq[4][i].out;
		multi_or[33][i].in[8] <== eq[3][i].out;
		multi_or[33][i].in[9] <== eq[11][i].out;
		and[66][i].b <== multi_or[33][i].out;
		states[i+1][37] <== and[66][i].out;
		state_changed[i].in[36] <== states[i+1][37];
		and[67][i] = AND();
		and[67][i].a <== states[i][37];
		multi_or[34][i] = MultiOR(10);
		multi_or[34][i].in[0] <== eq[8][i].out;
		multi_or[34][i].in[1] <== eq[6][i].out;
		multi_or[34][i].in[2] <== eq[12][i].out;
		multi_or[34][i].in[3] <== eq[2][i].out;
		multi_or[34][i].in[4] <== eq[7][i].out;
		multi_or[34][i].in[5] <== eq[9][i].out;
		multi_or[34][i].in[6] <== eq[10][i].out;
		multi_or[34][i].in[7] <== eq[11][i].out;
		multi_or[34][i].in[8] <== eq[4][i].out;
		multi_or[34][i].in[9] <== eq[3][i].out;
		and[67][i].b <== multi_or[34][i].out;
		states[i+1][38] <== and[67][i].out;
		state_changed[i].in[37] <== states[i+1][38];
		eq[27][i] = IsEqual();
		eq[27][i].in[0] <== in[i];
		eq[27][i].in[1] <== 42;
		and[68][i] = AND();
		and[68][i].a <== states[i][38];
		and[68][i].b <== eq[27][i].out;
		states[i+1][39] <== and[68][i].out;
		state_changed[i].in[38] <== states[i+1][39];
		and[69][i] = AND();
		and[69][i].a <== states[i][39];
		and[69][i].b <== eq[27][i].out;
		states[i+1][40] <== and[69][i].out;
		state_changed[i].in[39] <== states[i+1][40];
		and[70][i] = AND();
		and[70][i].a <== states[i][40];
		and[70][i].b <== eq[27][i].out;
		states[i+1][41] <== and[70][i].out;
		state_changed[i].in[40] <== states[i+1][41];
		and[71][i] = AND();
		and[71][i].a <== states[i][41];
		and[71][i].b <== eq[27][i].out;
		states[i+1][42] <== and[71][i].out;
		state_changed[i].in[41] <== states[i+1][42];
		and[72][i] = AND();
		and[72][i].a <== states[i][42];
		multi_or[35][i] = MultiOR(10);
		multi_or[35][i].in[0] <== eq[9][i].out;
		multi_or[35][i].in[1] <== eq[2][i].out;
		multi_or[35][i].in[2] <== eq[7][i].out;
		multi_or[35][i].in[3] <== eq[4][i].out;
		multi_or[35][i].in[4] <== eq[12][i].out;
		multi_or[35][i].in[5] <== eq[8][i].out;
		multi_or[35][i].in[6] <== eq[3][i].out;
		multi_or[35][i].in[7] <== eq[11][i].out;
		multi_or[35][i].in[8] <== eq[6][i].out;
		multi_or[35][i].in[9] <== eq[10][i].out;
		and[72][i].b <== multi_or[35][i].out;
		states[i+1][43] <== and[72][i].out;
		state_changed[i].in[42] <== states[i+1][43];
		and[73][i] = AND();
		and[73][i].a <== states[i][43];
		multi_or[36][i] = MultiOR(10);
		multi_or[36][i].in[0] <== eq[7][i].out;
		multi_or[36][i].in[1] <== eq[4][i].out;
		multi_or[36][i].in[2] <== eq[3][i].out;
		multi_or[36][i].in[3] <== eq[11][i].out;
		multi_or[36][i].in[4] <== eq[10][i].out;
		multi_or[36][i].in[5] <== eq[12][i].out;
		multi_or[36][i].in[6] <== eq[8][i].out;
		multi_or[36][i].in[7] <== eq[9][i].out;
		multi_or[36][i].in[8] <== eq[2][i].out;
		multi_or[36][i].in[9] <== eq[6][i].out;
		and[73][i].b <== multi_or[36][i].out;
		states[i+1][44] <== and[73][i].out;
		state_changed[i].in[43] <== states[i+1][44];
		and[74][i] = AND();
		and[74][i].a <== states[i][44];
		multi_or[37][i] = MultiOR(10);
		multi_or[37][i].in[0] <== eq[12][i].out;
		multi_or[37][i].in[1] <== eq[6][i].out;
		multi_or[37][i].in[2] <== eq[9][i].out;
		multi_or[37][i].in[3] <== eq[7][i].out;
		multi_or[37][i].in[4] <== eq[4][i].out;
		multi_or[37][i].in[5] <== eq[10][i].out;
		multi_or[37][i].in[6] <== eq[2][i].out;
		multi_or[37][i].in[7] <== eq[3][i].out;
		multi_or[37][i].in[8] <== eq[11][i].out;
		multi_or[37][i].in[9] <== eq[8][i].out;
		and[74][i].b <== multi_or[37][i].out;
		states[i+1][45] <== and[74][i].out;
		state_changed[i].in[44] <== states[i+1][45];
		and[75][i] = AND();
		and[75][i].a <== states[i][45];
		multi_or[38][i] = MultiOR(10);
		multi_or[38][i].in[0] <== eq[12][i].out;
		multi_or[38][i].in[1] <== eq[10][i].out;
		multi_or[38][i].in[2] <== eq[3][i].out;
		multi_or[38][i].in[3] <== eq[11][i].out;
		multi_or[38][i].in[4] <== eq[8][i].out;
		multi_or[38][i].in[5] <== eq[2][i].out;
		multi_or[38][i].in[6] <== eq[6][i].out;
		multi_or[38][i].in[7] <== eq[9][i].out;
		multi_or[38][i].in[8] <== eq[7][i].out;
		multi_or[38][i].in[9] <== eq[4][i].out;
		and[75][i].b <== multi_or[38][i].out;
		states[i+1][46] <== and[75][i].out;
		state_changed[i].in[45] <== states[i+1][46];
		states[i+1][0] <== 1 - state_changed[i].out;
	}

	component final_state_result = MultiOR(num_bytes+1);
	for (var i = 0; i <= num_bytes; i++) {
		final_state_result.in[i] <== states[i][46];
	}
	out <== final_state_result.out;
	signal is_consecutive[msg_bytes+1][2];
	is_consecutive[msg_bytes][1] <== 1;
	for (var i = 0; i < msg_bytes; i++) {
		is_consecutive[msg_bytes-1-i][0] <== states[num_bytes-i][46] * (1 - is_consecutive[msg_bytes-i][1]) + is_consecutive[msg_bytes-i][1];
		is_consecutive[msg_bytes-1-i][1] <== state_changed[msg_bytes-i].out * is_consecutive[msg_bytes-1-i][0];
	}
	// substrings calculated: [{(7, 11), (9, 7), (8, 9), (6, 7), (11, 13), (13, 15), (6, 8), (8, 7), (9, 11)}, {(42, 43), (45, 46), (36, 37), (33, 34), (44, 45), (37, 38), (39, 40), (40, 41), (38, 39), (34, 35), (41, 42), (32, 33), (35, 36), (43, 44)}]
	signal is_substr0[msg_bytes][10];
	signal is_reveal0[msg_bytes];
	signal output reveal0[msg_bytes];
	for (var i = 0; i < msg_bytes; i++) {
		is_substr0[i][0] <== 0;
		is_substr0[i][1] <== is_substr0[i][0] + states[i+1][6] * states[i+2][7];
		is_substr0[i][2] <== is_substr0[i][1] + states[i+1][6] * states[i+2][8];
		is_substr0[i][3] <== is_substr0[i][2] + states[i+1][7] * states[i+2][11];
		is_substr0[i][4] <== is_substr0[i][3] + states[i+1][8] * states[i+2][7];
		is_substr0[i][5] <== is_substr0[i][4] + states[i+1][8] * states[i+2][9];
		is_substr0[i][6] <== is_substr0[i][5] + states[i+1][9] * states[i+2][7];
		is_substr0[i][7] <== is_substr0[i][6] + states[i+1][9] * states[i+2][11];
		is_substr0[i][8] <== is_substr0[i][7] + states[i+1][11] * states[i+2][13];
		is_substr0[i][9] <== is_substr0[i][8] + states[i+1][13] * states[i+2][15];
		is_reveal0[i] <== is_substr0[i][9] * is_consecutive[i][1];
		reveal0[i] <== in[i+1] * is_reveal0[i];
	}
	signal is_substr1[msg_bytes][15];
	signal is_reveal1[msg_bytes];
	signal output reveal1[msg_bytes];
	for (var i = 0; i < msg_bytes; i++) {
		is_substr1[i][0] <== 0;
		is_substr1[i][1] <== is_substr1[i][0] + states[i+1][32] * states[i+2][33];
		is_substr1[i][2] <== is_substr1[i][1] + states[i+1][33] * states[i+2][34];
		is_substr1[i][3] <== is_substr1[i][2] + states[i+1][34] * states[i+2][35];
		is_substr1[i][4] <== is_substr1[i][3] + states[i+1][35] * states[i+2][36];
		is_substr1[i][5] <== is_substr1[i][4] + states[i+1][36] * states[i+2][37];
		is_substr1[i][6] <== is_substr1[i][5] + states[i+1][37] * states[i+2][38];
		is_substr1[i][7] <== is_substr1[i][6] + states[i+1][38] * states[i+2][39];
		is_substr1[i][8] <== is_substr1[i][7] + states[i+1][39] * states[i+2][40];
		is_substr1[i][9] <== is_substr1[i][8] + states[i+1][40] * states[i+2][41];
		is_substr1[i][10] <== is_substr1[i][9] + states[i+1][41] * states[i+2][42];
		is_substr1[i][11] <== is_substr1[i][10] + states[i+1][42] * states[i+2][43];
		is_substr1[i][12] <== is_substr1[i][11] + states[i+1][43] * states[i+2][44];
		is_substr1[i][13] <== is_substr1[i][12] + states[i+1][44] * states[i+2][45];
		is_substr1[i][14] <== is_substr1[i][13] + states[i+1][45] * states[i+2][46];
		is_reveal1[i] <== is_substr1[i][14] * is_consecutive[i][1];
		reveal1[i] <== in[i+1] * is_reveal1[i];
	}
}