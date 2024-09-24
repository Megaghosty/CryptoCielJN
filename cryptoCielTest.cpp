// RsaCiel.cpp : Ce fichier contient la fonction 'main'. L'exécution du programme commence et se termine à cet endroit.
//

#include <iostream>
#include "RsaGestion.h"
#include "Hashgestion.h"
#include "AesGestion.h"
#include <fstream>

int main()
{
	HashGestion LM;
	std::string File = "test.txt";
	std::cout << LM.CalculateFileSHA256(File) << std::endl;
	


	AesGestion Cia;
	Cia.GenerateAESKey();
	Cia.SaveAESKeyToFile("Cia_code.key");
	Cia.EncryptFileAES256("test.txt", "testencrypt.txt");
	Cia.DecryptFileAES256("testencrypt.txt", "testdecrypt.txt");

	RsaGestion Fbi;
	Fbi.generationClef("clef_pub.pem", "clef_pr.pem",2048);
	Fbi.chargementClefsPrive("clef_pr.pem");
	Fbi.chargementClefsPublic("clef_pub.pem");
	Fbi.chiffreDansFichier("message", "test1.txt");
	
	std::string micode = "test1.txt";
	std::cout << Fbi.dechiffreFichier(micode) << std::endl;
	
	RsaGestion NSA;
	NSA.generationClef("NSC_publ1c.pem", "NSC_pr1v.pem", 2048);
	NSA.chargementClefsPrive("NSC_pr1v.pem");
	NSA.chargementClefsPublic("NSC_publ1c.pem");
	NSA.chiffreDansFichier("1010101", "test2.txt");

	

	return 0;
	
}
