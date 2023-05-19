package com.mballem.curso.security.dto;

import java.io.Serializable;
import java.time.LocalDate;

/**
 * dto para formulario ajax
 */
public class MedicoDto implements Serializable {
    
    private String nome;
    private String crm;
    private LocalDate dtInscricao;
    private String[] especialidades;

    public String getNome() {
        return nome;
    }

    public void setNome(String nome) {
        this.nome = nome;
    }

    public String getCrm() {
        return crm;
    }

    public void setCrm(String crm) {
        this.crm = crm;
    }

    public LocalDate getDtInscricao() {
        return dtInscricao;
    }

    public void setDtInscricao(LocalDate dtInscricao) {
        this.dtInscricao = dtInscricao;
    }

    public String[] getEspecialidades() {
        return especialidades;
    }

    public void setEspecialidades(String[] especialidades) {
        this.especialidades = especialidades;
    }

}
