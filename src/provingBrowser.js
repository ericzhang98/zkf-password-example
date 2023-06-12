var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var nodecrypto = require('crypto');
var snarkjs = require("snarkjs");
var proofComponent = document.getElementById('proof');
var resultProofComponent = document.getElementById('resultProof');
var resultPublicSignalsComponent = document.getElementById('resultPublicSignals');
var bGenProof = document.getElementById("bGenProof");
var passwordInput = document.getElementById("passwordInput");
bGenProof.addEventListener("click", calculateProof);
function calculateProof() {
    return __awaiter(this, void 0, void 0, function () {
        var password, hashedPassword, hashedPasswordInt, _a, proof, publicSignals, fullProof, vKey, expectedPublicOutput, proofVerify, publicSignalsVerify;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    password = passwordInput.value;
                    console.log("password input:", password);
                    hashedPassword = nodecrypto.createHash('sha256').update(password).digest('hex');
                    console.log("hashed password:", hashedPassword);
                    hashedPasswordInt = parseInt(hashedPassword, 16);
                    console.log("integer encoding:", hashedPasswordInt);
                    return [4 /*yield*/, snarkjs.groth16.fullProve({ x: hashedPasswordInt }, "hash.wasm", "hash.zkey")];
                case 1:
                    _a = _b.sent(), proof = _a.proof, publicSignals = _a.publicSignals;
                    fullProof = { proof: proof, publicSignals: publicSignals };
                    proofComponent.innerHTML = JSON.stringify(fullProof, null, 1);
                    vKey = JSON.parse('{"protocol":"groth16","curve":"bn128","nPublic":1,"vk_alpha_1":["20491192805390485299153009773594534940189261866228447918068658471970481763042","9383485363053290200918347156157836566562967994039712273449902621266178545958","1"],"vk_beta_2":[["6375614351688725206403948262868962793625744043794305715222011528459656738731","4252822878758300859123897981450591353533073413197771768651442665752259397132"],["10505242626370262277552901082094356697409835680220590971873171140371331206856","21847035105528745403288232691147584728191162732299865338377159692350059136679"],["1","0"]],"vk_gamma_2":[["10857046999023057135944570762232829481370756359578518086990519993285655852781","11559732032986387107991004021392285783925812861821192530917403151452391805634"],["8495653923123431417604973247489272438418190587263600148770280649306958101930","4082367875863433681332203403145435568316851327593401208105741076214120093531"],["1","0"]],"vk_delta_2":[["2331074035208661256364667123862169704061449951851910379325063964198285430221","21173502052847522712343920695345049565520895905384250222105697507142194555901"],["961901284356507153388088069199380552581103880001797976871193700998289486054","1921085277078744684511176971830319952173319902281081603728474458216922605612"],["1","0"]],"vk_alphabeta_12":[[["2029413683389138792403550203267699914886160938906632433982220835551125967885","21072700047562757817161031222997517981543347628379360635925549008442030252106"],["5940354580057074848093997050200682056184807770593307860589430076672439820312","12156638873931618554171829126792193045421052652279363021382169897324752428276"],["7898200236362823042373859371574133993780991612861777490112507062703164551277","7074218545237549455313236346927434013100842096812539264420499035217050630853"]],[["7077479683546002997211712695946002074877511277312570035766170199895071832130","10093483419865920389913245021038182291233451549023025229112148274109565435465"],["4595479056700221319381530156280926371456704509942304414423590385166031118820","19831328484489333784475432780421641293929726139240675179672856274388269393268"],["11934129596455521040620786944827826205713621633706285934057045369193958244500","8037395052364110730298837004334506829870972346962140206007064471173334027475"]]],"IC":[["19990386180581831872975756587083647846854377024713147807401120019927814510470","1374289990345280532951462222754930685279598370257706216195209287842277075293","1"],["15660857620088070033679813165888800950528187939237475331372351214042129610404","10028534651145733259310265192844223678399370249915057066128208927027549606311","1"]]}');
                    expectedPublicOutput = '2739947043113102211213481732989651354652885696224258258437228137624096577594';
                    return [4 /*yield*/, snarkjs.groth16.verify(vKey, publicSignals, proof)];
                case 2:
                    proofVerify = _b.sent();
                    publicSignalsVerify = publicSignals[0] === expectedPublicOutput;
                    resultProofComponent.innerHTML = proofVerify;
                    resultPublicSignalsComponent.innerHTML = String(publicSignalsVerify);
                    return [2 /*return*/];
            }
        });
    });
}
