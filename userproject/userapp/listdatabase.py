
import pymysql
mydb= pymysql.connect(host='localhost',user='root',password='root',database='list')
cursor= mydb.cursor()


# a=['519', '3242', '3243', '3244', '3245', '3246', '3247', '3248', '3249', '7217', '26267', '26271', '28562', '31693', '31694', '31695', '31700', '31703', '31704', '31705', '31706', '31707', '31708', '31709', '31713', '31714', '31715', '31716', '31717', '31718', '31719', '31720', '31722', '31723', '31724', '31725', '31726', '31727', '31728', '31729', '31730', '31731', '31732', '31733', '31734', '31735', '31736', '31737', '31738', '31739', '31740', '31741', '31742', '31743', '31744', '31745', '31746', '31747', '31748', '31749', '31750', '31751', '31752', '31754', '31755', '31756', '31757', '31758', '31759', '31760', '31761', '31762', '31764', '31765', '31766', '31767', '31768', '31769', '31770', '31771', '31772', '31773', '31774', '31775', '31776', '31777', '31778', '31779', '31780', '31781', '31782', '31783', '31784', '31785', '31786', '31787', '31788', '31789', '31790', '31791', '31792', '31793', '31794', '31795', '31796', '31797', '31798', '31799', '31800', '31801', '31802', '31803', '31804', '31805', '31806', '31807', '31808', '31809', '31810', '31811', '31812', '31813', '31814', '31815', '31816', '31817', '31818', '31819', '31820', '31821', '31822', '31823', '31824', '31825', '31826', '31827', '31828', '31829', '31830', '31831', '31832', '31833', '31834', '31835', '31836', '31837', '31838', '31839', '31840', '31841', '31842', '31843', '31844', '31845', '31846', '31847', '31848', '31849', '31850', '31851', '31852', '31853', '31854', '31855', '31856', '31857', '31858', '31859', '31860', '31861', '31862', '31863', '31864', '31865', '31866', '31868', '31869', '31870', '31871', '31872', '31873', '31874', '31875', '31876', '31877', '31878', '31879', '31880', '31881', '31882', '31883', '31884', '31885', '31886', '31887', '31888', '31889', '31890', '31891', '31892', '31893', '31894', '31895', '31896', '31897', '31898', '31899', '31900', '31901', '31902', '31903', '31904', '31905', '31906', '31907', '31908', '31909', '31910', '31911', '31912', '31913', '31914', '31915', '31916', '31918', '31919', '31920', '31922', '31923', '31924', '31925', '31926', '31927', '31928', '31929', '31930', '31931', '31932', '31933', '31934', '31935', '31936', '31937', '31938', '31939', '31940', '31941', '31942', '31943', '31944', '31945', '31946', '31947', '31948', '31949', '31950', '31951', '31952', '31953', '31954', '31955', '31956', '31957', '31958', '31959', '31961', '31962', '31963', '31964', '31965', '31966', '31967', '31968', '31969', '31970', '31971', '31972', '31973', '31974', '31975', '31976', '31977', '31978', '31979', '31980', '31981', '31982', '31983', '31984', '31985', '31986', '31987', '31988', '31989', '31990', '31991', '31992', '31993', '31994', '31995', '31996', '31997', '31998', '31999', '32000', '32001', '32002', '32003', '32004', '32005', '32006', '32007', '32008', '32009', '32010', '32011', '32012', '32013', '32014', '32015', '32016', '32018', '32019', '32020', '32021', '32022', '32023', '32024', '32025', '32026', '32027', '32028', '32029', '32030', '32031', '32032', '32033', '32034', '32035', '32036', '32037', '32038', '32039', '32040', '32041', '32042', '32043', '32044', '32045', '32046', '32047', '32048', '32049', '32050', '32051', '32052', '32053', '32054', '32055', '32056', '32057', '32058', '32059', '32060', '32061', '32062', '32063', '32064', '32065', '32066', '32067', '32068', '32069', '32070', '32071', '32072', '32073', '32074', '32075', '32076', '32077', '32078', '32079', '32080', '32081', '32082', '32083', '32084', '32085', '32086', '32087', '32088', '32089', '32090', '32091', '32092', '32093', '32094', '32095', '32096', '32097', '32098', '32099', '32100', '32101', '32102', '32103', '32104', '32105', '32106', '32107', '32108', '32109', '32110', '32111', '32112', '32113', '32114', '32115', '32116', '32117', '32118', '32119', '32120', '32121', '32122', '32123', '32124', '32125', '32126', '32127', '32128', '32129', '32130', '32131', '32132', '32133', '32134', '32135', '32136', '32137', '32138', '32139', '32140', '32141', '32142', '32143', '32144', '32145', '32146', '32147', '32148', '32149', '32150', '32151', '32152', '32153', '32154', '32155', '32156', '32157', '32158', '32159', '32160', '32161', '32162', '32163', '32164', '32165', '32166', '32168', '32169', '32170', '32171', '32172', '32173', '32174', '32176', '32177', '32178', '32179', '32180', '32181', '32182', '32183', '32184', '32185', '32186', '32187', '32188', '32189', '32190', '32192', '32193', '32194', '32195', '32196', '32197', '32198', '32199', '32200', '32201', '32202', '32203', '32204', '32205', '32206', '32207', '32208', '32209', '32210', '32211', '32212', '32213', '32214', '32215', '32216', '32217', '32218', '32219', '32220', '32221', '32222', '32223', '32224', '32225', '32226', '32227', '32228', '32229', '32230', '32231', '32232', '32233', '32234', '32235', '32236', '32237', '32238', '32239', '32240', '32241', '32242', '32243', '32244', '32245', '32246', '32247', '32248', '32249', '32250', '32251', '32252', '32253', '32254', '32255', '32256', '32257', '32258', '32259', '32260', '32261', '32262', '32263', '32264', '32265', '32266', '32267', '32268', '32269', '32270', '32271', '32272', '32273', '32274', '32275', '32276', '32277', '32278', '32279', '32280', '32281', '32283', '32286', '32287', '32288', '32289', '32290', '32292', '32293', '32294', '32295', '32296', '32297', '32298', '32299', '32300', '32301', '32302', '32303', '32499', '32500', '32501', '32502', '32504', '32505', '32633', '32634', '32635', '32636', '32756', '32796', '32836', '32839', '32855', '32858', '32885', '32889', '32893', '32898', '32902', '32906', '32907', '32909', '32910', '32911', '32912', '32913', '32914', '32915', '32916', '32917', '32918', '32919', '32920', '32921', '32922', '32923', '32924', '32925', '32926', '32927', '32928', '32929', '32930', '32931', '32932', '32933', '32934', '32935', '32936', '32937', '32938', '32939', '32940', '32941', '32942', '32943', '32944', '32945', '32946', '32947', '32948', '32949', '32950', '32951', '32952', '32953', '32954', '32955', '32956', '32957', '32958', '32959', '32960', '32961', '32962', '32963', '32964', '32965', '32966', '32967', '32968', '32969', '32970', '32971', '32972', '32973', '32974', '32975', '32976', '32977', '32978', '32979', '32980', '32981', '32982', '32983', '32984', '32985', '32986', '32987', '32988', '32989', '32990', '32991', '32992', '32993', '32994', '32995', '32996', '32997', '32998', '32999', '33000', '33001', '33002', '33003', '33004', '33005', '33006', '33007', '33008', '33009', '33010', '33011', '33012', '33013', '33014', '33015', '33016', '33017', '33018', '33019', '33020', '33021', '33022', '33023', '33024', '33025', '33026', '33027', '33029', '33030', '33031', '33032', '33033', '33034', '33035', '33036', '33037', '33038', '33039', '33040', '33041', '33042', '33043', '33044', '33045', '33046', '33047', '33048', '33049', '33050', '33051', '33052', '33053', '33054', '33057', '33063', '33068', '33071', '33072', '33074', '33075', '33076', '33077', '33078', '33080', '33082', '33083', '33087', '33090', '33095', '33100', '33104', '33108', '33110', '33111', '33116', '33123', '33127', '33130', '33132', '33134', '33137', '33142', '33143', '33144', '33150', '33154', '33159', '33164', '33168', '33173', '33178', '33182', '33186', '33191', '33196', '33197', '33199', '33200', '33201', '33203', '33204', '33206', '33207', '33208', '33209', '33210', '33211', '33212', '33214', '33215', '33216', '33218', '33219', '33220', '33221', '33224', '33225', '33226', '33227', '33228', '33230', '33231', '33232', '33233', '33234', '33235', '33237', '33238', '33239', '33241', '33242', '33243', '33245', '33246', '33247', '33249', '33250', '33252', '33253', '33254', '33255', '33257', '33258', '33259', '33261', '33263', '33264', '33266', '33267', '33269', '33270', '33272', '33273', '33274', '33275', '33277', '33278', '33279', '33281', '33283', '33284', '33285', '33287', '33289', '33296', '33299', '33311', '33312', '33314', '33316', '33319', '33324', '33328', '33329', '33330', '33331', '33333', '33337', '33339', '33343', '33348', '33353', '33356', '33360', '33362', '33367', '33372', '33376', '33377', '33378', '33379', '33381', '33382', '33383', '33384', '33385', '33387', '33388', '33389', '33390', '33391', '33394', '33396', '33401', '33405', '33408', '33411', '33415', '33418', '33420', '33421', '33423', '33427', '33431', '33434', '33435', '33438', '33441', '33442', '33443', '33448', '33452', '33455', '33457', '33462', '33466']
# b=str(a)
# insert_stmt = "INSERT INTO listdata(data) VALUES (%s);"
# data1 = cursor.execute(insert_stmt,b)
# mydb.commit()
cursor.execute("select data from listdata where id =1;")
listdat1 = cursor.fetchone()
print(listdat1)
data=listdat1

for i in data:
    if "33466" in i:
        print("yes")
    else:
        print("NO")