.code
_sw_interrupt proc
  shl rcx, 3
  mov rax, jump_table
  add rax, rcx
  jmp qword ptr [rax]

I0:
  int 0
  ret
I1:
  int 1
  ret
I2:
  int 2
  ret
I3:
  int 3
  ret
I4:
  int 4
  ret
I5:
  int 5
  ret
I6:
  int 6
  ret
I7:
  int 7
  ret
I8:
  int 8
  ret
I9:
  int 9
  ret
I10:
  int 10
  ret
I11:
  int 11
  ret
I12:
  int 12
  ret
I13:
  int 13
  ret
I14:
  int 14
  ret
I15:
  int 15
  ret
I16:
  int 16
  ret
I17:
  int 17
  ret
I18:
  int 18
  ret
I19:
  int 19
  ret
I20:
  int 20
  ret
I21:
  int 21
  ret
I22:
  int 22
  ret
I23:
  int 23
  ret
I24:
  int 24
  ret
I25:
  int 25
  ret
I26:
  int 26
  ret
I27:
  int 27
  ret
I28:
  int 28
  ret
I29:
  int 29
  ret
I30:
  int 30
  ret
I31:
  int 31
  ret
I32:
  int 32
  ret
I33:
  int 33
  ret
I34:
  int 34
  ret
I35:
  int 35
  ret
I36:
  int 36
  ret
I37:
  int 37
  ret
I38:
  int 38
  ret
I39:
  int 39
  ret
I40:
  int 40
  ret
I41:
  int 41
  ret
I42:
  int 42
  ret
I43:
  int 43
  ret
I44:
  int 44
  ret
I45:
  int 45
  ret
I46:
  int 46
  ret
I47:
  int 47
  ret
I48:
  int 48
  ret
I49:
  int 49
  ret
I50:
  int 50
  ret
I51:
  int 51
  ret
I52:
  int 52
  ret
I53:
  int 53
  ret
I54:
  int 54
  ret
I55:
  int 55
  ret
I56:
  int 56
  ret
I57:
  int 57
  ret
I58:
  int 58
  ret
I59:
  int 59
  ret
I60:
  int 60
  ret
I61:
  int 61
  ret
I62:
  int 62
  ret
I63:
  int 63
  ret
I64:
  int 64
  ret
I65:
  int 65
  ret
I66:
  int 66
  ret
I67:
  int 67
  ret
I68:
  int 68
  ret
I69:
  int 69
  ret
I70:
  int 70
  ret
I71:
  int 71
  ret
I72:
  int 72
  ret
I73:
  int 73
  ret
I74:
  int 74
  ret
I75:
  int 75
  ret
I76:
  int 76
  ret
I77:
  int 77
  ret
I78:
  int 78
  ret
I79:
  int 79
  ret
I80:
  int 80
  ret
I81:
  int 81
  ret
I82:
  int 82
  ret
I83:
  int 83
  ret
I84:
  int 84
  ret
I85:
  int 85
  ret
I86:
  int 86
  ret
I87:
  int 87
  ret
I88:
  int 88
  ret
I89:
  int 89
  ret
I90:
  int 90
  ret
I91:
  int 91
  ret
I92:
  int 92
  ret
I93:
  int 93
  ret
I94:
  int 94
  ret
I95:
  int 95
  ret
I96:
  int 96
  ret
I97:
  int 97
  ret
I98:
  int 98
  ret
I99:
  int 99
  ret
I100:
  int 100
  ret
I101:
  int 101
  ret
I102:
  int 102
  ret
I103:
  int 103
  ret
I104:
  int 104
  ret
I105:
  int 105
  ret
I106:
  int 106
  ret
I107:
  int 107
  ret
I108:
  int 108
  ret
I109:
  int 109
  ret
I110:
  int 110
  ret
I111:
  int 111
  ret
I112:
  int 112
  ret
I113:
  int 113
  ret
I114:
  int 114
  ret
I115:
  int 115
  ret
I116:
  int 116
  ret
I117:
  int 117
  ret
I118:
  int 118
  ret
I119:
  int 119
  ret
I120:
  int 120
  ret
I121:
  int 121
  ret
I122:
  int 122
  ret
I123:
  int 123
  ret
I124:
  int 124
  ret
I125:
  int 125
  ret
I126:
  int 126
  ret
I127:
  int 127
  ret
I128:
  int 128
  ret
I129:
  int 129
  ret
I130:
  int 130
  ret
I131:
  int 131
  ret
I132:
  int 132
  ret
I133:
  int 133
  ret
I134:
  int 134
  ret
I135:
  int 135
  ret
I136:
  int 136
  ret
I137:
  int 137
  ret
I138:
  int 138
  ret
I139:
  int 139
  ret
I140:
  int 140
  ret
I141:
  int 141
  ret
I142:
  int 142
  ret
I143:
  int 143
  ret
I144:
  int 144
  ret
I145:
  int 145
  ret
I146:
  int 146
  ret
I147:
  int 147
  ret
I148:
  int 148
  ret
I149:
  int 149
  ret
I150:
  int 150
  ret
I151:
  int 151
  ret
I152:
  int 152
  ret
I153:
  int 153
  ret
I154:
  int 154
  ret
I155:
  int 155
  ret
I156:
  int 156
  ret
I157:
  int 157
  ret
I158:
  int 158
  ret
I159:
  int 159
  ret
I160:
  int 160
  ret
I161:
  int 161
  ret
I162:
  int 162
  ret
I163:
  int 163
  ret
I164:
  int 164
  ret
I165:
  int 165
  ret
I166:
  int 166
  ret
I167:
  int 167
  ret
I168:
  int 168
  ret
I169:
  int 169
  ret
I170:
  int 170
  ret
I171:
  int 171
  ret
I172:
  int 172
  ret
I173:
  int 173
  ret
I174:
  int 174
  ret
I175:
  int 175
  ret
I176:
  int 176
  ret
I177:
  int 177
  ret
I178:
  int 178
  ret
I179:
  int 179
  ret
I180:
  int 180
  ret
I181:
  int 181
  ret
I182:
  int 182
  ret
I183:
  int 183
  ret
I184:
  int 184
  ret
I185:
  int 185
  ret
I186:
  int 186
  ret
I187:
  int 187
  ret
I188:
  int 188
  ret
I189:
  int 189
  ret
I190:
  int 190
  ret
I191:
  int 191
  ret
I192:
  int 192
  ret
I193:
  int 193
  ret
I194:
  int 194
  ret
I195:
  int 195
  ret
I196:
  int 196
  ret
I197:
  int 197
  ret
I198:
  int 198
  ret
I199:
  int 199
  ret
I200:
  int 200
  ret
I201:
  int 201
  ret
I202:
  int 202
  ret
I203:
  int 203
  ret
I204:
  int 204
  ret
I205:
  int 205
  ret
I206:
  int 206
  ret
I207:
  int 207
  ret
I208:
  int 208
  ret
I209:
  int 209
  ret
I210:
  int 210
  ret
I211:
  int 211
  ret
I212:
  int 212
  ret
I213:
  int 213
  ret
I214:
  int 214
  ret
I215:
  int 215
  ret
I216:
  int 216
  ret
I217:
  int 217
  ret
I218:
  int 218
  ret
I219:
  int 219
  ret
I220:
  int 220
  ret
I221:
  int 221
  ret
I222:
  int 222
  ret
I223:
  int 223
  ret
I224:
  int 224
  ret
I225:
  int 225
  ret
I226:
  int 226
  ret
I227:
  int 227
  ret
I228:
  int 228
  ret
I229:
  int 229
  ret
I230:
  int 230
  ret
I231:
  int 231
  ret
I232:
  int 232
  ret
I233:
  int 233
  ret
I234:
  int 234
  ret
I235:
  int 235
  ret
I236:
  int 236
  ret
I237:
  int 237
  ret
I238:
  int 238
  ret
I239:
  int 239
  ret
I240:
  int 240
  ret
I241:
  int 241
  ret
I242:
  int 242
  ret
I243:
  int 243
  ret
I244:
  int 244
  ret
I245:
  int 245
  ret
I246:
  int 246
  ret
I247:
  int 247
  ret
I248:
  int 248
  ret
I249:
  int 249
  ret
I250:
  int 250
  ret
I251:
  int 251
  ret
I252:
  int 252
  ret
I253:
  int 253
  ret
I254:
  int 254
  ret
I255:
  int 255
  ret

.data
jump_table:
  dq I0
  dq I1
  dq I2
  dq I3
  dq I4
  dq I5
  dq I6
  dq I7
  dq I8
  dq I9
  dq I10
  dq I11
  dq I12
  dq I13
  dq I14
  dq I15
  dq I16
  dq I17
  dq I18
  dq I19
  dq I20
  dq I21
  dq I22
  dq I23
  dq I24
  dq I25
  dq I26
  dq I27
  dq I28
  dq I29
  dq I30
  dq I31
  dq I32
  dq I33
  dq I34
  dq I35
  dq I36
  dq I37
  dq I38
  dq I39
  dq I40
  dq I41
  dq I42
  dq I43
  dq I44
  dq I45
  dq I46
  dq I47
  dq I48
  dq I49
  dq I50
  dq I51
  dq I52
  dq I53
  dq I54
  dq I55
  dq I56
  dq I57
  dq I58
  dq I59
  dq I60
  dq I61
  dq I62
  dq I63
  dq I64
  dq I65
  dq I66
  dq I67
  dq I68
  dq I69
  dq I70
  dq I71
  dq I72
  dq I73
  dq I74
  dq I75
  dq I76
  dq I77
  dq I78
  dq I79
  dq I80
  dq I81
  dq I82
  dq I83
  dq I84
  dq I85
  dq I86
  dq I87
  dq I88
  dq I89
  dq I90
  dq I91
  dq I92
  dq I93
  dq I94
  dq I95
  dq I96
  dq I97
  dq I98
  dq I99
  dq I100
  dq I101
  dq I102
  dq I103
  dq I104
  dq I105
  dq I106
  dq I107
  dq I108
  dq I109
  dq I110
  dq I111
  dq I112
  dq I113
  dq I114
  dq I115
  dq I116
  dq I117
  dq I118
  dq I119
  dq I120
  dq I121
  dq I122
  dq I123
  dq I124
  dq I125
  dq I126
  dq I127
  dq I128
  dq I129
  dq I130
  dq I131
  dq I132
  dq I133
  dq I134
  dq I135
  dq I136
  dq I137
  dq I138
  dq I139
  dq I140
  dq I141
  dq I142
  dq I143
  dq I144
  dq I145
  dq I146
  dq I147
  dq I148
  dq I149
  dq I150
  dq I151
  dq I152
  dq I153
  dq I154
  dq I155
  dq I156
  dq I157
  dq I158
  dq I159
  dq I160
  dq I161
  dq I162
  dq I163
  dq I164
  dq I165
  dq I166
  dq I167
  dq I168
  dq I169
  dq I170
  dq I171
  dq I172
  dq I173
  dq I174
  dq I175
  dq I176
  dq I177
  dq I178
  dq I179
  dq I180
  dq I181
  dq I182
  dq I183
  dq I184
  dq I185
  dq I186
  dq I187
  dq I188
  dq I189
  dq I190
  dq I191
  dq I192
  dq I193
  dq I194
  dq I195
  dq I196
  dq I197
  dq I198
  dq I199
  dq I200
  dq I201
  dq I202
  dq I203
  dq I204
  dq I205
  dq I206
  dq I207
  dq I208
  dq I209
  dq I210
  dq I211
  dq I212
  dq I213
  dq I214
  dq I215
  dq I216
  dq I217
  dq I218
  dq I219
  dq I220
  dq I221
  dq I222
  dq I223
  dq I224
  dq I225
  dq I226
  dq I227
  dq I228
  dq I229
  dq I230
  dq I231
  dq I232
  dq I233
  dq I234
  dq I235
  dq I236
  dq I237
  dq I238
  dq I239
  dq I240
  dq I241
  dq I242
  dq I243
  dq I244
  dq I245
  dq I246
  dq I247
  dq I248
  dq I249
  dq I250
  dq I251
  dq I252
  dq I253
  dq I254
  dq I255
.code
_sw_interrupt endp
END
